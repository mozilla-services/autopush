import os
import unittest
import uuid
from datetime import datetime, timedelta

from autopush.websocket import ms_time
from botocore.exceptions import ClientError
from mock import Mock, patch
import pytest

from autopush.config import DDBTableConfig
from autopush.db import (
    get_rotating_message_tablename,
    create_router_table,
    preflight_check,
    table_exists,
    Message,
    Router,
    generate_last_connect,
    make_rotating_tablename,
    create_rotating_message_table,
    _drop_table,
    _make_table,
    DatabaseManager,
    DynamoDBResource
    )
from autopush.exceptions import AutopushException, ItemNotFound
from autopush.metrics import SinkMetrics
from autopush.utils import WebPushNotification

# nose fails to import sessions correctly.
import autopush.tests

dummy_uaid = str(uuid.UUID("abad1dea00000000aabbccdd00000000"))
dummy_chid = str(uuid.UUID("deadbeef00000000decafbad00000000"))

test_router = None


def setup_module():
    global test_router
    config = DDBTableConfig("router_test")
    test_router = Router(config, SinkMetrics(),
                         resource=autopush.tests.boto_resource)


def make_webpush_notification(uaid, chid, ttl=100):
    message_id = str(uuid.uuid4())
    return WebPushNotification(
        uaid=uuid.UUID(uaid),
        channel_id=uuid.UUID(chid),
        update_id=message_id,
        message_id=message_id,
        ttl=ttl,
    )


class DbUtilsTest(unittest.TestCase):
    def test_make_table(self):
        fake_resource = Mock()
        fake_func = Mock()
        fake_table = "DoesNotExist_{}".format(uuid.uuid4())

        _make_table(fake_func, fake_table, 5, 10, boto_resource=fake_resource)
        assert fake_func.call_args[0] == (fake_table, 5, 10, fake_resource)

    def test_make_table_no_resource(self):
        fake_func = Mock()
        fake_table = "DoesNotExist_{}".format(uuid.uuid4())

        with pytest.raises(AutopushException) as ex:
            _make_table(fake_func, fake_table, 5, 10,
                        boto_resource=None)
        assert str(ex.value) == "No boto3 resource provided for _make_table"


class DatabaseManagerTest(unittest.TestCase):
    def fake_conf(self, table_name=""):
        fake_conf = Mock()
        fake_conf.statsd_host = "localhost"
        fake_conf.statsd_port = 8125
        fake_conf.allow_table_rotation = False
        fake_conf.message_table = Mock()
        fake_conf.message_table.tablename = table_name
        fake_conf.message_table.read_throughput = 5
        fake_conf.message_table.write_throughput = 5
        return fake_conf

    def test_init_with_resources(self):
        from autopush.db import DynamoDBResource
        dm = DatabaseManager(router_conf=Mock(),
                             message_conf=Mock(),
                             metrics=Mock(),
                             resource=None)
        assert dm.resource is not None
        assert isinstance(dm.resource, DynamoDBResource)

    def test_init_with_no_rotate(self):
        fake_conf = self.fake_conf("message_int_test")
        dm = DatabaseManager.from_config(
            fake_conf,
            resource=autopush.tests.boto_resource)
        dm.create_initial_message_tables()
        assert dm.current_msg_month == \
            autopush.tests.boto_resource.get_latest_message_tablename(
                prefix=fake_conf.message_table.tablename
            )

    def test_init_with_no_rotate_create_table(self):
        fake_conf = self.fake_conf("message_bogus")
        dm = DatabaseManager.from_config(
            fake_conf,
            resource=autopush.tests.boto_resource)
        try:
            dm.create_initial_message_tables()
            latest = autopush.tests.boto_resource.get_latest_message_tablename(
                    prefix=fake_conf.message_table.tablename
                )
            assert dm.current_msg_month == latest
            assert dm.message_tables == [fake_conf.message_table.tablename]
        finally:
            # clean up the bogus table.
            dm.resource._resource.meta.client.delete_table(
                TableName=fake_conf.message_table.tablename)


class DdbResourceTest(unittest.TestCase):
    @patch("boto3.resource")
    def test_ddb_no_endpoint(self, mresource):
        safe = os.getenv("AWS_LOCAL_DYNAMODB")
        try:
            os.unsetenv("AWS_LOCAL_DYANMODB")
            del(os.environ["AWS_LOCAL_DYNAMODB"])
            DynamoDBResource(region_name="us-east-1")
            assert mresource.call_args[0] == ('dynamodb',)
            resource = DynamoDBResource(endpoint_url="")
            assert resource.conf == {}
        finally:
            if safe:  # pragma: nocover
                os.environ["AWS_LOCAL_DYNAMODB"] = safe

    def test_ddb_env(self):
        ddb_session_args = dict(
            endpoint_url=os.getenv("AWS_LOCAL_DYNAMODB"),
            aws_access_key_id="BogusKey",
            aws_secret_access_key="BogusKey",
        )
        safe = os.getenv("AWS_DEFAULT_REGION")
        try:
            os.environ["AWS_DEFAULT_REGION"] = "us-west-2"
            boto_resource = DynamoDBResource(**ddb_session_args)
            assert boto_resource._resource.meta.client.meta.region_name == \
                'us-west-2'
        finally:
            if safe:  # pragma: nocover
                os.environ["AWS_DEFAULT_REGION"] = safe


class DbCheckTestCase(unittest.TestCase):
    def setUp(cls):
        cls.resource = autopush.tests.boto_resource
        cls.table_conf = DDBTableConfig("router_test")
        cls.router = Router(cls.table_conf, SinkMetrics(),
                            resource=cls.resource)

    def test_preflight_check_fail(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        message = Message(get_rotating_message_tablename(
            boto_resource=self.resource),
            boto_resource=self.resource)

        def raise_exc(*args, **kwargs):  # pragma: no cover
            raise Exception("Oops")

        router.clear_node = Mock()
        router.clear_node.side_effect = raise_exc

        with pytest.raises(Exception):
            preflight_check(message, router, self.resource)

    def test_preflight_check(self):
        global test_router
        message = Message(get_rotating_message_tablename(
            boto_resource=self.resource),
            boto_resource=self.resource)

        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(message, test_router, pf_uaid)
        # now check that the database reports no entries.
        _, notifs = message.fetch_messages(uuid.UUID(pf_uaid))
        assert len(notifs) == 0
        with pytest.raises(ItemNotFound):
            self.router.get_uaid(pf_uaid)

    def test_preflight_check_wait(self):
        global test_router
        message = Message(
            get_rotating_message_tablename(boto_resource=self.resource),
            boto_resource=self.resource
        )

        values = ["PENDING", "ACTIVE"]
        message.table_status = Mock(side_effect=values)

        pf_uaid = "deadbeef00000000deadbeef01010101"
        preflight_check(message, test_router, pf_uaid)
        # now check that the database reports no entries.
        _, notifs = message.fetch_messages(uuid.UUID(pf_uaid))
        assert len(notifs) == 0
        with pytest.raises(ItemNotFound):
            self.router.get_uaid(pf_uaid)

    def test_get_month(self):
        from autopush.db import get_month
        month0 = get_month(0)
        month1 = get_month(1)
        this_month = month0.month
        next_month = 1 if this_month == 12 else this_month + 1
        assert next_month == month1.month

    def test_zero_fill_month(self):
        from autopush.db import make_rotating_tablename
        assert 'test_2016_03' == make_rotating_tablename(
            'test', date=datetime(2016, 3, 15).date())

    def test_hasher(self):
        import autopush.db as db
        db.key_hash = "SuperSikkret"
        v = db.hasher("01234567123401234123456789ABCDEF")
        assert v == ('0530bb351921e7b4be66831e4c126c6'
                     'd8f614d06cdd592cb8470f31177c8331a')
        db.key_hash = ""

    def test_normalize_id(self):
        # Note, yes, we forbid dashes in UAIDs, and we add them here.
        import autopush.db as db
        abnormal = "deadbeef00000000decafbad00000000"
        normal = "deadbeef-0000-0000-deca-fbad00000000"
        assert db.normalize_id(abnormal) == normal
        with pytest.raises(ValueError):
            db.normalize_id("invalid")
        assert db.normalize_id(abnormal.upper()) == normal


class MessageTestCase(unittest.TestCase):
    def setUp(self):
        self.resource = autopush.tests.boto_resource
        table = get_rotating_message_tablename(
            prefix="message_int_test",
            boto_resource=self.resource)
        self.real_table = table
        self.uaid = uuid.uuid4().hex

    def test_non_rotating_tables(self):
        message_tablename = "message_int_test"
        table_name = self.resource.get_latest_message_tablename(
            prefix=message_tablename)
        message = Message(table_name,
                          boto_resource=self.resource)
        assert message.tablename == table_name

    def test_register(self):
        chid = str(uuid.uuid4())

        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)
        lm = self.resource.Table(m)
        # Verify it's in the db
        response = lm.query(
            KeyConditions={
                'uaid': {
                    'AttributeValueList': [self.uaid],
                    'ComparisonOperator': 'EQ'
                },
                'chidmessageid': {
                    'AttributeValueList': ['02'],
                    'ComparisonOperator': 'LT'
                }
            },
            ConsistentRead=True,
        )
        assert len(response.get('Items'))

    def test_unregister(self):
        chid = str(uuid.uuid4())
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)

        # Verify its in the db
        lm = self.resource.Table(m)
        # Verify it's in the db
        response = lm.query(
            KeyConditions={
                'uaid': {
                    'AttributeValueList': [self.uaid],
                    'ComparisonOperator': 'EQ'
                },
                'chidmessageid': {
                    'AttributeValueList': [" "],
                    'ComparisonOperator': 'EQ'
                },
            },
            ConsistentRead=True,
        )
        results = list(response.get('Items'))
        assert len(results) == 1
        assert results[0]["chids"] == {chid}

        message.unregister_channel(self.uaid, chid)

        # Verify its not in the db
        response = lm.query(
            KeyConditions={
                'uaid': {
                    'AttributeValueList': [self.uaid],
                    'ComparisonOperator': 'EQ'
                },
                'chidmessageid': {
                    'AttributeValueList': [" "],
                    'ComparisonOperator': 'EQ'
                },
            },
            ConsistentRead=True,
        )
        results = list(response.get('Items'))
        assert len(results) == 1
        assert results[0].get("chids") is None

        # Test for the very unlikely case that there's no 'chid'
        mtable = Mock()
        mtable.update_item = Mock(return_value={
            'Attributes': {'uaid': self.uaid},
            'ResponseMetaData': {}
        })
        message.table = mtable
        r = message.unregister_channel(self.uaid, dummy_chid)
        assert r is False

    def test_all_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        _, chans = message.all_channels(self.uaid)
        assert chid in chans
        assert chid2 in chans

        message.unregister_channel(self.uaid, chid2)
        _, chans = message.all_channels(self.uaid)
        assert chid2 not in chans
        assert chid in chans

    def test_all_channels_fail(self):

        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)

        mtable = Mock()
        mtable.get_item.return_value = {
            "ResponseMetadata": {
                "HTTPStatusCode": 400
            },
        }
        message.table = mtable
        res = message.all_channels(self.uaid)
        assert res == (False, set([]))

    def test_save_channels(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        exists, chans = message.all_channels(self.uaid)
        new_uaid = uuid.uuid4().hex
        message.save_channels(new_uaid, chans)
        _, new_chans = message.all_channels(new_uaid)
        assert chans == new_chans

    def test_all_channels_no_uaid(self):
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        exists, chans = message.all_channels(dummy_uaid)
        assert chans == set([])

    def test_message_storage(self):
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        # Ensure that sort keys are fetched from DB in order.
        notifs = [make_webpush_notification(self.uaid, chid) for x in range(3)]
        keys = [notif.sort_key for notif in notifs]
        for msg in notifs:
            message.store_message(msg)

        _, all_messages = message.fetch_timestamp_messages(
            uuid.UUID(self.uaid), " ")
        assert len(all_messages) == len(notifs)
        assert keys == [msg.sort_key for msg in all_messages]

    def test_message_storage_overwrite(self):
        """Test that store_message can overwrite existing messages which
        can occur in some reconnect cases but shouldn't error"""
        chid = str(uuid.uuid4())
        chid2 = str(uuid.uuid4())
        notif1 = make_webpush_notification(self.uaid, chid)
        notif2 = make_webpush_notification(self.uaid, chid)
        notif3 = make_webpush_notification(self.uaid, chid2)
        notif2.message_id = notif1.message_id
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)
        message.register_channel(self.uaid, chid)
        message.register_channel(self.uaid, chid2)

        message.store_message(notif1)
        message.store_message(notif2)
        message.store_message(notif3)

        all_messages = list(message.fetch_messages(
            uuid.UUID(self.uaid)))
        assert len(all_messages) == 2

    def test_message_delete_fail_condition(self):
        notif = make_webpush_notification(dummy_uaid, dummy_chid)
        notif.message_id = notif.update_id = dummy_uaid
        m = get_rotating_message_tablename(boto_resource=self.resource)
        message = Message(m, boto_resource=self.resource)

        def raise_condition(*args, **kwargs):
            raise ClientError({}, 'delete_item')

        m_de = Mock()
        m_de.delete_item = Mock(side_effect=raise_condition)
        message.table = m_de
        result = message.delete_message(notif)
        assert result is False

    def test_message_rotate_table_with_date(self):
        prefix = "message" + uuid.uuid4().hex
        future = (datetime.today() + timedelta(days=32)).date()
        tbl_name = make_rotating_tablename(prefix, date=future)

        m = get_rotating_message_tablename(prefix=prefix, date=future,
                                           boto_resource=self.resource)
        assert m == tbl_name
        # Clean up the temp table.
        _drop_table(tbl_name, boto_resource=self.resource)


class RouterTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resource = autopush.tests.boto_resource
        cls.table_conf = DDBTableConfig("router_test")
        cls.router = test_router

    def _create_minimal_record(self):
        data = {
            "uaid": str(uuid.uuid4()),
            "router_type": "webpush",
            "last_connect": generate_last_connect(),
            "connected_at": ms_time(),
            "current_month": datetime.today().month,
        }
        return data

    def test_old_mobile_user(self):
        # Old mobile users (ones that use a bridge) don't regularly check
        # in, or update their expiry record. It's important that we don't
        # drop them because reconnecting requires a re-installation.
        old_mobile = self._create_minimal_record()
        old_mobile["expiry"] = None
        m_user = old_mobile['uaid']
        self.router.register_user(old_mobile)
        # verify that fetching a user without a expiry still works.
        # old mobile users don't have, and may never get, and expiry
        user = self.router.get_uaid(m_user)
        assert user["uaid"] == m_user

    def test_custom_tablename(self):
        db_name = "router_%s" % uuid.uuid4()
        assert not table_exists(db_name, boto_resource=self.resource)
        create_router_table(db_name, boto_resource=self.resource)
        assert table_exists(db_name, boto_resource=self.resource)
        # Clean up the temp table.
        _drop_table(db_name, boto_resource=self.resource)

    def test_create_rotating_cache(self):
        mock_table = Mock()
        mock_table.table_status = 'ACTIVE'
        mock_resource = Mock()
        mock_resource.Table = Mock(return_value=mock_table)
        table = create_rotating_message_table(boto_resource=mock_resource)
        assert table == mock_table

    def test_provisioning(self):
        db_name = "router_%s" % uuid.uuid4()

        r = create_router_table(db_name, 3, 17,
                                boto_resource=self.resource)
        assert r.provisioned_throughput.get('ReadCapacityUnits') == 3
        assert r.provisioned_throughput.get('WriteCapacityUnits') == 17

    def test_no_uaid_found(self):
        uaid = str(uuid.uuid4())
        with pytest.raises(ItemNotFound):
            self.router.get_uaid(uaid)

    def test_uaid_provision_failed(self):
        router = Router(self.table_conf,  SinkMetrics(),
                        resource=self.resource)
        router.table = Mock()

        def raise_condition(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                'mock_update_item'
            )

        mm = Mock()
        mm.get_item = Mock(side_effect=raise_condition)
        router.table = mm
        with pytest.raises(ClientError) as ex:
            router.get_uaid(uaid="asdf")
        assert (ex.value.response['Error']['Code'] ==
                "ProvisionedThroughputExceededException")

    def test_register_user_provision_failed(self):
        router = Router(self.table_conf, SinkMetrics(), resource=self.resource)
        mm = Mock()
        mm.client = Mock()

        router.table = mm

        def raise_condition(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                'mock_update_item'
            )

        mm.update_item = Mock(side_effect=raise_condition)
        with pytest.raises(ClientError) as ex:
            router.register_user(dict(uaid=dummy_uaid, node_id="me",
                                      connected_at=1234,
                                      router_type="webpush"))
        assert (ex.value.response['Error']['Code'] ==
                "ProvisionedThroughputExceededException")

    def test_register_user_condition_failed(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        router.table.meta.client = Mock()

        def raise_error(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException'}},
                'mock_update_item'
            )
        mm = Mock()
        mm.update_item = Mock(side_effect=raise_error)
        router.table = mm
        res = router.register_user(dict(uaid=dummy_uaid, node_id="me",
                                        connected_at=1234,
                                        router_type="webpush"))
        assert res == (False, {})

    def test_clear_node_provision_failed(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)

        def raise_condition(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                'mock_update_item'
            )

        mm = Mock()
        mm.put_item = Mock(side_effect=raise_condition)
        router.table = mm
        with pytest.raises(ClientError) as ex:
            router.clear_node(dict(uaid=dummy_uaid,
                                   connected_at="1234",
                                   node_id="asdf",
                                   router_type="webpush"))
        assert (ex.value.response['Error']['Code'] ==
                "ProvisionedThroughputExceededException")

    def test_clear_node_condition_failed(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)

        def raise_error(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException'}},
                'mock_put_item'
            )

        mock_put = Mock()
        mock_put.put_item = Mock(side_effect=raise_error)
        router.table = mock_put
        res = router.clear_node(dict(uaid=dummy_uaid,
                                     connected_at="1234",
                                     node_id="asdf",
                                     router_type="webpush"))

        assert res is False

    def test_incomplete_uaid(self):
        # Older records may be incomplete. We can't inject them using normal
        # methods.
        uaid = str(uuid.uuid4())
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        mm = Mock()
        mm.get_item = Mock()
        mm.get_item.return_value = {
            "ResponseMetadata": {
                "HTTPStatusCode": 200
            },
            "Item": {
                "uaid": uuid.uuid4().hex
            }
        }
        mm.delete_item.return_value = {
            "ResponseMetadata": {
                "HTTPStatusCode": 200
            },
        }
        router.table = mm
        router.drop_user = Mock()
        try:
            router.register_user(dict(uaid=uaid))
        except AutopushException:
            pass
        with pytest.raises(ItemNotFound):
            router.get_uaid(uaid)
        assert router.drop_user.called

    def test_failed_uaid(self):
        uaid = str(uuid.uuid4())
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        mm = Mock()
        mm.get_item = Mock()
        mm.get_item.return_value = {
            "ResponseMetadata": {
                "HTTPStatusCode": 400
            },
        }
        router.table = mm
        router.drop_user = Mock()
        with pytest.raises(ItemNotFound):
            router.get_uaid(uaid)

    def test_save_new(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        # Sadly, moto currently does not return an empty value like boto
        # when not updating data.
        mock_update = Mock()
        mock_update.update_item = Mock(return_value={})
        router.table = mock_update
        result = router.register_user(dict(uaid=dummy_uaid,
                                           node_id="me",
                                           router_type="webpush",
                                           connected_at=1234))
        assert result[0] is True

    def test_save_fail(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)

        def raise_condition(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException'}},
                'mock_update_item'
            )

        mock_update = Mock()
        mock_update.update_item = Mock(side_effect=raise_condition)
        router.table = mock_update
        router_data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234,
                           router_type="webpush")
        result = router.register_user(router_data)
        assert result == (False, {})

    def test_node_clear(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)

        # Register a node user
        router.register_user(dict(uaid=dummy_uaid, node_id="asdf",
                                  connected_at=1234,
                                  router_type="webpush"))
        # Verify
        user = router.get_uaid(dummy_uaid)
        assert user["node_id"] == "asdf"
        assert user["connected_at"] == 1234
        assert user["router_type"] == "webpush"

        # Clear
        router.clear_node(user)

        # Verify
        user = router.get_uaid(dummy_uaid)
        assert user.get("node_id") is None
        assert user["connected_at"] == 1234
        assert user["router_type"] == "webpush"

    def test_node_clear_fail(self):
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)

        def raise_condition(*args, **kwargs):
            raise ClientError(
                {'Error': {'Code': 'ConditionalCheckFailedException'}},
                'mock_update_item'
            )

        mock_put = Mock()
        mock_put.put_item = Mock(side_effect=raise_condition)
        router.table = mock_put
        data = dict(uaid=dummy_uaid, node_id="asdf", connected_at=1234)
        result = router.clear_node(data)
        assert result is False

    def test_drop_user(self):
        uaid = str(uuid.uuid4())
        router = Router(self.table_conf, SinkMetrics(),
                        resource=self.resource)
        # Register a node user
        router.register_user(dict(uaid=uaid, node_id="asdf",
                                  router_type="webpush",
                                  connected_at=1234))
        result = router.drop_user(uaid)
        assert result is True
        # Deleting already deleted record should return false.
        result = router.drop_user(uaid)
        assert result is False

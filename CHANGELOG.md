<a name="1.29.1"></a>
## 1.29.1 (2017-05-05)


#### Features

*   update parquet schema for unified parquet logging ([2aeefce7](https://github.com/mozilla-services/autopush/commit/2aeefce732d44281c25f0b07cd3c650d837de2ba), closes [#888](https://github.com/mozilla-services/autopush/issues/888))



<a name="1.29.0"></a>
## 1.29.0 (2017-04-28)


#### Refactor

*   refine the Handler validation ([b1312db7](https://github.com/mozilla-services/autopush/commit/b1312db7e2e9932daf997c5ade72e9353aaa9bd0))

#### Bug Fixes

*   revert registration's strict critical failure check ([caf2ed8d](https://github.com/mozilla-services/autopush/commit/caf2ed8d12372918475b619c391c39a62eb1d9c3))
*   Do not report InvalidSignature as unhandled ([0d243556](https://github.com/mozilla-services/autopush/commit/0d2435566598af35d3583467a26d82016259fe53))
*   enforce `senderID` for gcm/fcm ([569dd1ff](https://github.com/mozilla-services/autopush/commit/569dd1ff6baeead93b98abe5996de3208771dfc9))

#### Features

*   add parquet unified schema and cleanup logging messages ([63d2981c](https://github.com/mozilla-services/autopush/commit/63d2981c3e804adc84877ccb643515f139ce7787), closes [#882](https://github.com/mozilla-services/autopush/issues/882))
*   add tracking for content-encoding ([c236f725](https://github.com/mozilla-services/autopush/commit/c236f72505344261c530e13ea61f42aaffd06bbd))
*   Add VAPID Draft 02 support ([e17129db](https://github.com/mozilla-services/autopush/commit/e17129dbc2022ae6d3c856e7c94354bd4151df89))



<a name="1.28.0"></a>
## 1.28.0 (2017-04-07)


#### Refactor

*   cleanup some deferred arg bookkeeping ([55e91c59](https://github.com/mozilla-services/autopush/commit/55e91c59d449c57b1a3d19d803656b8d4323818d))
*   various cleanup ([013db1ca](https://github.com/mozilla-services/autopush/commit/013db1ca1c2d904d78ecca9adb243eb5462d69e2))

#### Features

*   Use cryptography based JWT parser for increased speed ([fe9b7766](https://github.com/mozilla-services/autopush/commit/fe9b7766e4af50452a2cb69fd982bf5c89f74523))

#### Bug Fixes

*   APNS may close a socket prematurely, resulting in an AttributeError ([ed86e267](https://github.com/mozilla-services/autopush/commit/ed86e26706fe0d07bc8849c8dae3e44a72ae0675))
*   Hyphenate `content-available`; don't send `alert` for APNs. ([103e0945](https://github.com/mozilla-services/autopush/commit/103e094508d06700e2d90d05f8a2b442438bbd97))
*   Limit exception trapping to known types when processing crypto-key ([3576d207](https://github.com/mozilla-services/autopush/commit/3576d2075b590861950b984160243de35bf982d5))
*   Fixes for missing UAID and header values ([defb331b](https://github.com/mozilla-services/autopush/commit/defb331b3f8df001a18ee2c58d8363d0929304d0))
*   Use log.error() to better track exceptions in APNS ([8aa510d7](https://github.com/mozilla-services/autopush/commit/8aa510d7c30d4d2748cf3d2d9330e8d3ffb85a78))



<a name="1.27.0"></a>
## 1.27.0 (2017-03-24)


#### Doc

*   Update docs ([9520e50d](https://github.com/mozilla-services/autopush/commit/9520e50dd5756422d415a746ab7784bfd185b92a))

#### Chore

*   utilize PEP 426 env markers ([b0a5983e](https://github.com/mozilla-services/autopush/commit/b0a5983ef9678849bac53bb3c600b955b0df296b))
*   kill the base requirements ([edf927b6](https://github.com/mozilla-services/autopush/commit/edf927b63be9959f182d7dafd0a327b3c893501e))
*   kill these to preserve history ([5242b3f1](https://github.com/mozilla-services/autopush/commit/5242b3f15d7dd359ccb067a818c64f78a58d9eaa))
*   peg the pypy version ([aa729dc6](https://github.com/mozilla-services/autopush/commit/aa729dc692e4da94a4a60a798b9f34231bad2b1c))

#### Features

*   Add ChannelID report for UAID ([71035fa0](https://github.com/mozilla-services/autopush/commit/71035fa0e95825c1058d1c3d8debade519c50c2a))
*   Add timeout for internally routed messages. ([44d02853](https://github.com/mozilla-services/autopush/commit/44d02853ca42d21f0c709951926353aa2a672b86))



<a name="1.26.0"></a>
## 1.26.0 (2017-03-10)


#### Bug Fixes

*   prefer the create method ([e7b34c30](https://github.com/mozilla-services/autopush/commit/e7b34c30055245f42eb2458b1964b166448a304b))
*   Don't send non-priority messages to sentry ([94465295](https://github.com/mozilla-services/autopush/commit/9446529575efa14021731a4c8a115096e0300f93))
*   Do not attempt to register failed GCM registrations ([896b3df1](https://github.com/mozilla-services/autopush/commit/896b3df17f2c35fec708dd9c8e275a1f01ad3754))
*   Do not attempt to register failed GCM registrations ([39bae0b8](https://github.com/mozilla-services/autopush/commit/39bae0b82f971b75c4f5944cbf9e90dff2bf200d))

#### Features

*   new slack channel ([569ae32f](https://github.com/mozilla-services/autopush/commit/569ae32f7cef3a289e392839c172f3c3affb917a))
*   also include pypyjit's get_stats_asmmemmgr ([fcf5b8b5](https://github.com/mozilla-services/autopush/commit/fcf5b8b5a0db92e27c04de8c3dc1715cb7e66454))
*   capture and metric item not found instead of log ([73e084f2](https://github.com/mozilla-services/autopush/commit/73e084f2be4bf4aef140f8f1127566d6a7ccaee2), closes [#811](https://github.com/mozilla-services/autopush/issues/811))



<a name="1.25.1"></a>
## 1.25.1 (2017-02-17)


#### Doc

*   git tag needs an explicit signing flag (and msg) ([e8b47821](https://github.com/mozilla-services/autopush/commit/e8b47821299cd91fc772eb200ee24b037d37af4d))

#### Bug Fixes

*   impl. a haproxy endpoint that actually wraps SSL ([f39886dd](https://github.com/mozilla-services/autopush/commit/f39886dd41e8bc0abb7a9d0fb6c54207dd9ff64b))
*   Correct docs to use correct HTTP method for subscription updates ([7b07c87f](https://github.com/mozilla-services/autopush/commit/7b07c87f48b5037de8bb5675f56abddfeaf7567d))
*   try to avoid build failures on pypy w/ with_gmp=no ([ebaeeb34](https://github.com/mozilla-services/autopush/commit/ebaeeb34245dc66d86a0f791c774842e94904762))
*   really fix coverage ([da614eb9](https://github.com/mozilla-services/autopush/commit/da614eb9b49f52517c205121c691f128b6d2a7f0))
*   a few minor type sig changes ([f8929dff](https://github.com/mozilla-services/autopush/commit/f8929dff686db101885ab48f5ceca7f852559c22))



<a name="1.25.0"></a>
## 1.25.0 (2017-02-10)


#### Features

*   add a /_memusage API on a separate (internal port) ([6a9336ce](https://github.com/mozilla-services/autopush/commit/6a9336cee6a1fc420523d561538a7102e71e5283))
*   add gcdump.py from pypy's tools ([a6360ea1](https://github.com/mozilla-services/autopush/commit/a6360ea13182538b121188ec525ac2778712d317))
*   add thorough jwt exp validation ([97d42136](https://github.com/mozilla-services/autopush/commit/97d4213655b0b78310a474e8ddb672d4cdb5449c), closes [#794](https://github.com/mozilla-services/autopush/issues/794))

#### Bug Fixes

*   fix coverage ([0bca3d18](https://github.com/mozilla-services/autopush/commit/0bca3d18a3a105aacd007b7a7e32c5acb2dca61d))
*   VAPID errors should return 401, not 404; handle InvalidToken exception for parse_endpoint ([03c513be](https://github.com/mozilla-services/autopush/commit/03c513bec9e6ae3cdaa58a5223bfb2f1394ca904))
*   ensure our LoopingCall failures are logged ([ac1e7a78](https://github.com/mozilla-services/autopush/commit/ac1e7a78ab7d4606f1a0c3c2ecbf24305debb53a))
*   APNs library requires parameters to be strings ([332505e1](https://github.com/mozilla-services/autopush/commit/332505e1827676806478ab36c9f3f5e5bb3f9afe))
*   zero pad months in table names ([f7d7c1c3](https://github.com/mozilla-services/autopush/commit/f7d7c1c35a72c490057826f39168734e969189ad))
*   Update to latest cryptography library ([d537fd83](https://github.com/mozilla-services/autopush/commit/d537fd83bd797891e08087a5749dc61af35885de))

#### Doc

*   add git signing note ([dbf52495](https://github.com/mozilla-services/autopush/commit/dbf524953a912b04ecf68c29a4156c8d1419a8aa), closes [#759](https://github.com/mozilla-services/autopush/issues/759))



<a name="1.24.0"></a>
## 1.24.0 (2017-01-27)


#### Features

*   switch proxy_protocol -> proxy_protocol_port (#789) ([81e3af47](https://github.com/mozilla-services/autopush/commit/81e3af47821320a7fddf0408ee50cfd1384b149e))

#### Bug Fixes

*   prefer the LogBeginner observer entry point ([dc64f8a5](https://github.com/mozilla-services/autopush/commit/dc64f8a5ddf444761b6670dc7db1ed7ab90976f7))

#### Test

*   pypy on travis and #560 (#790) ([a38660a0](https://github.com/mozilla-services/autopush/commit/a38660a09fbe710e1f1ca223598ae58665c25471))



<a name="1.23.0"></a>
## 1.23.0 (2017-01-11)


#### Bug Fixes

*   avoid the new webpush validation in these tests (#781) ([5266bb71](https://github.com/mozilla-services/autopush/commit/5266bb71f26ea60a44ab5e7883828c63c35b6e31))

#### Features

*   allow log_check/status/health API calls w/out certs (#783) ([34dc8842](https://github.com/mozilla-services/autopush/commit/34dc884212429057c60594c587c0d5593c4967b6))
*   add cache-control header to 410's (#773) ([2d386b8a](https://github.com/mozilla-services/autopush/commit/2d386b8a91b713fe4d84ef8e026e991a609dc5fd), closes [#770](https://github.com/mozilla-services/autopush/issues/770))
*   log the python version in client_info (#778) ([876c3825](https://github.com/mozilla-services/autopush/commit/876c3825b21d073108ff9d75c53caf5e047d4f4c))
*   Typos in docs (#782) ([7b25baee](https://github.com/mozilla-services/autopush/commit/7b25baeeb06a61627ace25d9ff986553c2f33d8e))
*   update docs and clarify error messages (#779) ([37689b33](https://github.com/mozilla-services/autopush/commit/37689b335fed391ea767e560e49bc977ff5ee285))
*   move preflight logic into webpush validation (#772) ([d963d181](https://github.com/mozilla-services/autopush/commit/d963d181246bfecb645567c85e85fed7e7699347), closes [#765](https://github.com/mozilla-services/autopush/issues/765))
*   Add request timing w/validation breakdown. ([b2a491cd](https://github.com/mozilla-services/autopush/commit/b2a491cd21bd1b52061300fbdf5f5565e94d0930), closes [#758](https://github.com/mozilla-services/autopush/issues/758))
*   add a --proxy_protocol for the partner endpoint ([f482e64d](https://github.com/mozilla-services/autopush/commit/f482e64dd63bb88398a318b5b2ddc52c94244f44))



<a name="1.22.0"></a>
## 1.22.0 (2016-11-28)


#### Features

*   enforce strict crypto header checks (#734) ([b4749d1d](https://github.com/mozilla-services/autopush/commit/b4749d1dda8a4c7162d7b4f266db64e31d547285), closes [#188](https://github.com/mozilla-services/autopush/issues/188))
*   add topic metric for messages sent with topics. ([8c13078b](https://github.com/mozilla-services/autopush/commit/8c13078bcc0db23bb5afe4c2e55b54fa03e653ea))

#### Bug Fixes

*   handle CryptoKeyExceptions in new crypto validation (#751) ([cefe4788](https://github.com/mozilla-services/autopush/commit/cefe4788af03dd8131d05f62832fbd42921d7081))
*   log router_key in web/webpush web/simplepush ([18cbfdfa](https://github.com/mozilla-services/autopush/commit/18cbfdfa1ea5ec7bc9dcfc215147c853f25e0bf9))
*   Add exception info to log.info call (#743) ([c43788c1](https://github.com/mozilla-services/autopush/commit/c43788c1cf139f7325751f2e9423c617c503278c))
*   kill lingering doc references to S3 (#741) ([00a2f9a3](https://github.com/mozilla-services/autopush/commit/00a2f9a39701df7d68dbdf23b3b3ee4616e069c6))



<a name="1.21.2"></a>
## 1.21.2 (2016-11-17)


#### Chore

*   tag 1.21.2 ([728f2606](https://github.com/mozilla-services/autopush/commit/728f2606b992c91de5df08cb370ca6bdbf392dc4))



<a name="1.21.1"></a>
## 1.21.1 (2016-11-17)


#### Bug Fixes

*   call defer methods with callables (#737) ([aff89047](https://github.com/mozilla-services/autopush/commit/aff8904791420c1c44c90f0c4c79a93fea105d6a))



<a name="1.21.0"></a>
## 1.21.0 (2016-11-10)


#### Breaking Changes

*   Kill v0 endpoints ([99e921c0](https://github.com/mozilla-services/autopush/commit/99e921c0c044f24acc076485538978a1ab2d941b), closes [#492](https://github.com/mozilla-services/autopush/issues/492))

#### Bug Fixes

*   Don't log exceptions that don't want to be logged ([8819b3d5](https://github.com/mozilla-services/autopush/commit/8819b3d5d981ad0bf8baf7818daded752d11513c))
*   reset UAID if too many messages are pending ([461a8661](https://github.com/mozilla-services/autopush/commit/461a8661c71a17dc4650100e790e8685109858fa))
*   Zero pad months in table names ([5ca85e07](https://github.com/mozilla-services/autopush/commit/5ca85e07609ef204dc743f13025bfce7f42596ad))

#### Features

*   Kill v0 endpoints ([99e921c0](https://github.com/mozilla-services/autopush/commit/99e921c0c044f24acc076485538978a1ab2d941b), closes [#492](https://github.com/mozilla-services/autopush/issues/492))
*   reset users missing a record version or expired version ([2ef3762d](https://github.com/mozilla-services/autopush/commit/2ef3762d8fdb54f73d5d52258c3f2df66fd7362b), closes [#711](https://github.com/mozilla-services/autopush/issues/711))
*   retain date when checking message tables (#727) ([04756c44](https://github.com/mozilla-services/autopush/commit/04756c440552ba35c51d040d6bcaac0847f0c963), closes [#722](https://github.com/mozilla-services/autopush/issues/722))
*   spread monthly rotation retry over 30 minutes (#726) ([7c084596](https://github.com/mozilla-services/autopush/commit/7c084596885e9e062cc1041f5242068d53e7ff1d), closes [#723](https://github.com/mozilla-services/autopush/issues/723))



<a name="1.20.0"></a>
## 1.20.0 (2016-10-28)


#### Bug Fixes

*   improve handling of JSONResponseErrors ([7dcb0a0d](https://github.com/mozilla-services/autopush/commit/7dcb0a0d2884dc7f717815594324c0c31550f1d5))
*   improve handling of JSONResponseErrors (#718) ([29ff0fe4](https://github.com/mozilla-services/autopush/commit/29ff0fe4e959958ba3c6e9578a3cb8a4d4c2ecf4))

#### Features

*   skip timestamped messages instead of deleting (#720) ([c2418107](https://github.com/mozilla-services/autopush/commit/c241810711aa8fa84dc8eded89e9aedf3cdea45c), closes [#661](https://github.com/mozilla-services/autopush/issues/661))
*   Add integration tests for bridges ([5bc3abe7](https://github.com/mozilla-services/autopush/commit/5bc3abe7b20818c9432d6784a958dced8f755bd8))
*   add type hints to autopush/utils.py (#713) ([12a9b7cd](https://github.com/mozilla-services/autopush/commit/12a9b7cd20596a1766d25e6c66db1694de8668b3))



<a name="1.19.3"></a>
## 1.19.3 (2016-10-17)


#### Bug Fixes

*   use hex formatted ChannelID strings for bridged connections (#709) ([8aa1a7eb](https://github.com/mozilla-services/autopush/commit/8aa1a7eb1266f792538723f35569ae13e0355adc))
*   kill websocket.Notification (#707) ([e564a974](https://github.com/mozilla-services/autopush/commit/e564a9746feafbb30f2548eef89889c172fc5bb6))



<a name="1.19.2"></a>
## 1.19.2 (2016-10-13)


#### Bug Fixes

*   correct headers to use transcoded values ([0e5e1e34](https://github.com/mozilla-services/autopush/commit/0e5e1e3405093c00271eee820eb5f128143b652f))
*   Set TTL to 0 if None when doing expiration checks (#701) ([0aab2a95](https://github.com/mozilla-services/autopush/commit/0aab2a95f4e635983d9a6104f1c8b05099c31131))
*   do not return error informtion for 500 errors for router ([5206cab6](https://github.com/mozilla-services/autopush/commit/5206cab634fe20337ec8a0c5a555633ad5ae7ff6))
*   simplify Message validation by passing WebPushNotification ([0a3d94da](https://github.com/mozilla-services/autopush/commit/0a3d94da33689142507d1f756b38290247e8b9bc))
*   Stop splitting version info when logging for websocket ([bd3c2c30](https://github.com/mozilla-services/autopush/commit/bd3c2c3034e622990883a42bf4ada5378ce2d1b0))
*   normalize channelids to JSON encodable entities ([777dff44](https://github.com/mozilla-services/autopush/commit/777dff4452a138dad82a6d9e7eb63180e1fec7c8))

#### Doc

*   minor updates to the release workflow (#690) ([cc7cc306](https://github.com/mozilla-services/autopush/commit/cc7cc306ade7c35c4e12029085e1d816a6423b14))



<a name="1.19.1"></a>
## 1.19.1 (2016-10-10)


#### Chore

*   kill unneeded deps: ([de1aeb62](https://github.com/mozilla-services/autopush/commit/de1aeb6219655a59285dc67e54780ebf0ef2063f))
*   tag 1.19.0 release (#685) ([3be87959](https://github.com/mozilla-services/autopush/commit/3be879590d1d64c2b451a675d696a0422a2cffd2))

#### Bug Fixes

*   validated methods ignore raw arguments ([dbbd0816](https://github.com/mozilla-services/autopush/commit/dbbd0816b474e47d25e1566cf101f90c9ef4f393))



<a name="1.19.0"></a>
## 1.19.0 (2016-10-07)


#### Features

*   move Message and Registration handlers to own validated class ([ea3b48c2](https://github.com/mozilla-services/autopush/commit/ea3b48c2fa9c3fa1c554f78fe5e367935b7aa10d))
*   handle provisioned errors gracefully (#682) ([8e5f52ad](https://github.com/mozilla-services/autopush/commit/8e5f52ad36f754013ea7fb4739b94bf5634ed7f7), closes [#658](https://github.com/mozilla-services/autopush/issues/658))
*   add user record cleanup script (#677) ([9e5a95f9](https://github.com/mozilla-services/autopush/commit/9e5a95f9004046e5195273c3d4ab7b12eaa7f63c), closes [#645](https://github.com/mozilla-services/autopush/issues/645))
*   include timestamps in tests' logs (#675) ([a3c3b82a](https://github.com/mozilla-services/autopush/commit/a3c3b82a38ed3ffe07c5e07855a009232eff8b1f))
*   add a new client_certs endpoint config option ([58e0cbbd](https://github.com/mozilla-services/autopush/commit/58e0cbbd3ebd83cff149d59281a81123a01ac428))
*   add webpush topics ([0fe241bb](https://github.com/mozilla-services/autopush/commit/0fe241bb8be36aefbdaa0a4e71549fb2355f40cd), closes [#643](https://github.com/mozilla-services/autopush/issues/643))
*   Switch to new http2 based APNS protocol ([15fea87d](https://github.com/mozilla-services/autopush/commit/15fea87d4ebe2f95f226eb4dfac6296d62fff04b))

#### Chore

*   remove the wsaccel dependency on pypy (#683) ([aa047f36](https://github.com/mozilla-services/autopush/commit/aa047f36f7d13c9a9094183cfaee9a289ccd8920))
*   fix travis' virtualenv giving us an older python (#664) ([f47b7435](https://github.com/mozilla-services/autopush/commit/f47b7435429771372a3d0ab2487fe5915129686e))

#### Bug Fixes

*   assertRaises -> assert_raises ([e417325c](https://github.com/mozilla-services/autopush/commit/e417325cfa740067414f87752ee2a855d59179aa))
*   assertTrue -> eq_ ([c01eb4de](https://github.com/mozilla-services/autopush/commit/c01eb4de19f0e9fe11f24d9028950b225e3ee383))
*   assertTrue -> ok_ ([db4e6dca](https://github.com/mozilla-services/autopush/commit/db4e6dca82ad38db66d27b5221ff6dbc5e1c5d7d))
*   adapt asserts to ok/eq_ ([e9fd8a1c](https://github.com/mozilla-services/autopush/commit/e9fd8a1c1ea9ac7e50af08136c7f352fed90aea4))
*   assert -> ok_ ([9b83d9c6](https://github.com/mozilla-services/autopush/commit/9b83d9c6d577437386380eaf688b6249d892d7fc))
*   remove extra jws_err handler which caused extra write after finish ([65c7a3a5](https://github.com/mozilla-services/autopush/commit/65c7a3a5c8216c759207df6fef599446b2c7491a))



<a name="1.18.0"></a>
## 1.18.0 (2016-09-20)


#### Bug Fixes

*   label arguments for router.register to prevent misassignment (#648) ([b1a7e2db](https://github.com/mozilla-services/autopush/commit/b1a7e2dbbaa13369e969b404ed76c474bc0a689b))
*   Require auth header for endpoints with v2 (#659) ([ee633a50](https://github.com/mozilla-services/autopush/commit/ee633a50ad06c4d137f6b0cfb7bf7318115fbbf6))
*   log all drop_user calls with record details when possible ([21c76f17](https://github.com/mozilla-services/autopush/commit/21c76f174fcec2fcc6d958791dc489ce1f8181de), closes [#650](https://github.com/mozilla-services/autopush/issues/650))
*   return webpush style response for bridged users ([a0339bbe](https://github.com/mozilla-services/autopush/commit/a0339bbe5fcc196cdb93db7905ebb0a547c54b19), closes [#651](https://github.com/mozilla-services/autopush/issues/651))

#### Features

*   Add multiple cert handlers for APNs ([7eed1ffe](https://github.com/mozilla-services/autopush/commit/7eed1ffe3f779af44c088c9ae2792c189956ef96), closes [#655](https://github.com/mozilla-services/autopush/issues/655), breaks [#](https://github.com/mozilla-services/autopush/issues/))
*   update jwt library ([68fccf99](https://github.com/mozilla-services/autopush/commit/68fccf994b5d354bca4f3706aa5de685b5fc6900))

#### Breaking Changes

*   Add multiple cert handlers for APNs ([7eed1ffe](https://github.com/mozilla-services/autopush/commit/7eed1ffe3f779af44c088c9ae2792c189956ef96), closes [#655](https://github.com/mozilla-services/autopush/issues/655), breaks [#](https://github.com/mozilla-services/autopush/issues/))



<a name="1.17.2"></a>
## 1.17.2 (2016-08-31)


#### Test

*   clarify where we mean IRouter vs db.Router ([33244055](https://github.com/mozilla-services/autopush/commit/332440558bef35668873307cebe390b714b6e467))

#### Chore

*   break out base deps into their own req file ([001e0da4](https://github.com/mozilla-services/autopush/commit/001e0da4d2cc87b578b01261db09f3925f0a8503))
*   git mv a break out of the base deps ([abc63330](https://github.com/mozilla-services/autopush/commit/abc633307466e9731b2a2f2ee7d49b50ee6de8e0))

#### Bug Fixes

*   provide better logging and fix UAID misreference ([704fd814](https://github.com/mozilla-services/autopush/commit/704fd81469e41ef5da522fff27fa1aae235c0bd4))
*   do not try to JSON serialize log output ([9861edb6](https://github.com/mozilla-services/autopush/commit/9861edb6f8ec506130591b4b5a13dbb16a1b2a52))
*   clarify token references in HTTP endpoint docs ([8a751472](https://github.com/mozilla-services/autopush/commit/8a7514721abc8d16bd487c1ef4560c5c5dfe9ba3))
*   add URI to error messages to aid in bad senderIDs ([05e5d00f](https://github.com/mozilla-services/autopush/commit/05e5d00f8b3974139a54310255ce4ef0a2cf6c7b))
*   kill dead_cache, it's no longer used ([2135dd8b](https://github.com/mozilla-services/autopush/commit/2135dd8b99b07798f7bb41ed15b6daf582feda32))
*   update Makefile to use correct requirements ([ec6418b3](https://github.com/mozilla-services/autopush/commit/ec6418b3183faf1ff94bfea537fcb981e4cb4494))
*   handle more errors to connection nodes ([3cc24fe8](https://github.com/mozilla-services/autopush/commit/3cc24fe876e47115cbe2993216d6e80a585f4a8e))
*   disable log_exception capturing in tests ([62074f74](https://github.com/mozilla-services/autopush/commit/62074f74f45b36afd8fa20f549a41ca6285fa398))
*   trap UnicodeEncodeError ([a116def7](https://github.com/mozilla-services/autopush/commit/a116def7bfbeb087bc80845dd2eda438515b3ccb), closes [#606](https://github.com/mozilla-services/autopush/issues/606))

#### Features

*   dependency update ([03ba5b56](https://github.com/mozilla-services/autopush/commit/03ba5b56c39d3d99ff317c0f08ade929b23652f9), closes [#639](https://github.com/mozilla-services/autopush/issues/639))
*   add docker-compose and revamp docs ([b4fb7c67](https://github.com/mozilla-services/autopush/commit/b4fb7c6771940f5c2067ba03895bd86186dd2c1b), closes [#559](https://github.com/mozilla-services/autopush/issues/559))
*   reduce warnings in code base ([a2308b99](https://github.com/mozilla-services/autopush/commit/a2308b99edbab0117bb7074f2b32b8eaf8f9beda))

#### Refactor

*   extract a simple BaseHandler ([a794e20f](https://github.com/mozilla-services/autopush/commit/a794e20fa82075d72644d0f358951cb5d0fed17b))
*   cleanup of Handler initialize/ap_settings ([031e1446](https://github.com/mozilla-services/autopush/commit/031e1446df485aab834a7664e67612d4d1920f8e))



<a name="1.17.1"></a>
## 1.17.1 (2016-08-22)


#### Refactor

*   prefer immutable class vars (follow up to 97a133a4) ([7ec831e7](https://github.com/mozilla-services/autopush/commit/7ec831e753495d1bddfc515a37653ff296fbd1d6))

#### Features

*   send sentry the current stack when lacking a Failure tb ([29a9dce8](https://github.com/mozilla-services/autopush/commit/29a9dce8d801dfedb09ecc7fcd3980549078633b))
*   Limit the size of allowed HTTP bodies & headers ([54c4526a](https://github.com/mozilla-services/autopush/commit/54c4526a63ee899fb69a5f37967a2dc39edf4208), closes [#501](https://github.com/mozilla-services/autopush/issues/501))
*   Validate Encryption/C-Key headers in preflight ([0c27efc2](https://github.com/mozilla-services/autopush/commit/0c27efc2f513037a1bc40bd268655626b2e0c775), closes [#456](https://github.com/mozilla-services/autopush/issues/456))
*   Allow both "Bearer" and "WebPush" as Auth tokens ([1891f913](https://github.com/mozilla-services/autopush/commit/1891f9137506d2eb67475fb2df0ee43278120e24), closes [#592](https://github.com/mozilla-services/autopush/issues/592))
*   better documentation for config files & locations ([71869826](https://github.com/mozilla-services/autopush/commit/71869826fa7d8e1e1bbc01fd7aaf167bd02cfed9), closes [#572](https://github.com/mozilla-services/autopush/issues/572))

#### Bug Fixes

*   limit max TTL for GCM/FCM ([7c14249a](https://github.com/mozilla-services/autopush/commit/7c14249afe667ce8ec3ea2b2dc8e2f8a17cbcf10))
*   Trap BOTO Server exception as 503's ([75a8889d](https://github.com/mozilla-services/autopush/commit/75a8889d64c095db74db6cda458413181822d4e5), closes [#605](https://github.com/mozilla-services/autopush/issues/605))
*   trap JWS/JWT errors from being reported as Sentry Errors ([3e0dd71c](https://github.com/mozilla-services/autopush/commit/3e0dd71ca3626ad106deeea662fec13cd0845cd5), closes [#610](https://github.com/mozilla-services/autopush/issues/610))
*   Trap BOTO Server exception as 503's ([95bc09c2](https://github.com/mozilla-services/autopush/commit/95bc09c2f8ce1a4c61ee0ab0170ce9923ff5b69a), closes [#605](https://github.com/mozilla-services/autopush/issues/605))
*   return 404 for invalid URL's for consistency ([f4c47af7](https://github.com/mozilla-services/autopush/commit/f4c47af7351aebc45f3781651fa24d0f1e939f98), closes [#578](https://github.com/mozilla-services/autopush/issues/578))
*   Prevent invalid header values from causing key errors in validation ([55e08bfc](https://github.com/mozilla-services/autopush/commit/55e08bfc331218a29aa790a8f0dcc6aba9b76a5b), closes [#604](https://github.com/mozilla-services/autopush/issues/604))
*   Check tokens in constant time ([ed7ce2b4](https://github.com/mozilla-services/autopush/commit/ed7ce2b40b2f09ce40902a4adfaec9b900f627d0), closes [#571](https://github.com/mozilla-services/autopush/issues/571))
*   fixes reference to releasing page ([8510397b](https://github.com/mozilla-services/autopush/commit/8510397b3bb24d3471e1d667ce7d0bc821874111))
*   kill duplicate ssl_key/cert options ([2d2e716c](https://github.com/mozilla-services/autopush/commit/2d2e716c1a5e263a0dc548516dbd9702c92d344e))
*   remove obsoleted options from sample config files, and mock_s3 which is no longer necessary ([aa4b4de4](https://github.com/mozilla-services/autopush/commit/aa4b4de42e78e2660746c42a576da589898115ad))
*   Update FCM handler to more accurately reflect API ([5f9c3223](https://github.com/mozilla-services/autopush/commit/5f9c32237d764ec33d7ba42e7df62989f90c8c8c))

#### Doc

*   describe configuration of SSL/TLS ([55f4dadb](https://github.com/mozilla-services/autopush/commit/55f4dadbc0d778145bdd3344b98923a27da6f1bf))
*   kill outdated comment ([82bf79b8](https://github.com/mozilla-services/autopush/commit/82bf79b8d8f949c2de725be2166c314962691959))



<a name="1.17.0"></a>
## 1.17.0 (2016-08-05)


#### Refactor

*   clarify intent of write methods returning nothing ([94ab2134](https://github.com/mozilla-services/autopush/commit/94ab2134e24b12b216eff01a9a079d11d63b0ed1))
*   utilize console_script's sys.exit return value to kill a mock ([1c7de067](https://github.com/mozilla-services/autopush/commit/1c7de0679e634771bcfe0f23bd565fab468db554))

#### Doc

*   add release process ([a5da4491](https://github.com/mozilla-services/autopush/commit/a5da4491cf7239db438f4e6521d1c726ccdf784a))
*   formatting/externalize the links ([966ada81](https://github.com/mozilla-services/autopush/commit/966ada816ea0cd85fb1455c5a448845f00029664))
*   updates to installation ([aa6729bb](https://github.com/mozilla-services/autopush/commit/aa6729bb0be270717ca35ed95e955bdd137a974c))
*   updates to intros ([efe0c652](https://github.com/mozilla-services/autopush/commit/efe0c652c01101ff41359a53818ecd613f9d7da8))

#### Test

*   don't hide wait_for_times test failures ([fe98d4c6](https://github.com/mozilla-services/autopush/commit/fe98d4c69b7f5c32adb4ba43a1a47fa95b1c1dfb))

#### Bug Fixes

*   remove readline from the nix pkg also ([e7c8d385](https://github.com/mozilla-services/autopush/commit/e7c8d38595a641420b747cb27255cb9e4a57c48c))
*   Allow old GCM senderID ([fe0d19c8](https://github.com/mozilla-services/autopush/commit/fe0d19c857d6beaf540fb7ca828b6defcbfe872b))
*   fix _base_tags class var usage and make other class vars immutable ([97a133a4](https://github.com/mozilla-services/autopush/commit/97a133a4829057d85869f83c83b7428578054302))
*   readline isn't needed ([834a2c79](https://github.com/mozilla-services/autopush/commit/834a2c7958b7eb04de464b14d4ebd4ec901accd3))
*   Do not remove router_type from UAID info ([d74c00c9](https://github.com/mozilla-services/autopush/commit/d74c00c94d593dc9b2fab8658e76b0f1bfea68f4))
*   Fix up FCM library to reject enpdoints with invalid FCM senderids ([56633e4c](https://github.com/mozilla-services/autopush/commit/56633e4cd21b1f15897a094e4d0046676b4b01aa), closes [#556](https://github.com/mozilla-services/autopush/issues/556))
*   Add ValueError trap for extract_jwt ([3f2af804](https://github.com/mozilla-services/autopush/commit/3f2af8044db8b04d05b4390ad495ac4b5d0a9100))
*   Do not record the GCM data overflow error ([b4e8ed43](https://github.com/mozilla-services/autopush/commit/b4e8ed439f223cd00d1b524e0544ddd7a792e4f9), closes [#552](https://github.com/mozilla-services/autopush/issues/552))
*   avoid uaid error in webpush preflight ([333d2fff](https://github.com/mozilla-services/autopush/commit/333d2fff0c0a1d833bd79676a4cf23cb2b682941))
*   test_bad_senderidlist now requires --gcm_enabled. bandaid handling of make_settings failures for now ([949f8d3a](https://github.com/mozilla-services/autopush/commit/949f8d3a98996c278ba67e6aa0cc96c59a24bec2))
*   Handle URL arguments to OPTIONS and HEAD requests ([471137f5](https://github.com/mozilla-services/autopush/commit/471137f5f7ecc8f87abed0ddd1fb4abf89d0b7c0))
*   nocover the util function ([6230f77d](https://github.com/mozilla-services/autopush/commit/6230f77d8af38608677e92cda5487938eec26cac))
*   kill now unused senderid_list cruft ([a2e1f8c8](https://github.com/mozilla-services/autopush/commit/a2e1f8c8faed5478048aa8aadd32af03acc82fa5))
*   kill mutable default arguments ([b405cce6](https://github.com/mozilla-services/autopush/commit/b405cce663ad0e245ff020b142e4af6f37389034))

#### Chore

*   more gitignores ([d5585c6c](https://github.com/mozilla-services/autopush/commit/d5585c6c83a14d2543cb58a9a67c735bf59f97b7))
* **Dockerfile:**  apt-get update before installing (#545) ([5c6cb3ce](https://github.com/mozilla-services/autopush/commit/5c6cb3ced6aef4ee205a4c28e8e8d51221099e4d))

#### Features

*   normalize user-agent for datadog and parse for raw logging ([8c4c6368](https://github.com/mozilla-services/autopush/commit/8c4c6368902b3f018e3093abee0813d1f46dbbba), closes [#487](https://github.com/mozilla-services/autopush/issues/487))
*   Add URLs, text to error response messages ([da5eca84](https://github.com/mozilla-services/autopush/commit/da5eca84d9494c4cc6b36d17198e4113633c8c23))
*   log all unregister/register calls. also adds assert_called_included for checking calls including kwargs ([cb87a82f](https://github.com/mozilla-services/autopush/commit/cb87a82f05b19e49599cbfc2c4fc0761dca03b7c))
*   Add FCM router support ([b06c6a75](https://github.com/mozilla-services/autopush/commit/b06c6a7519b2b5142bee57954c7bf5c4367ddc71))



<a name="1.16.1"></a>
## 1.16.1 (2016-07-19)


#### Bug Fixes

*   catch InvalidToken exceptions from fernet ([b00ae57c](https://github.com/mozilla-services/autopush/commit/b00ae57c2b6f6613ce81c0567815c7336cd30783), closes [#530](https://github.com/mozilla-services/autopush/issues/530))
*   overwrite existing messages instead of throwing an error ([aa738816](https://github.com/mozilla-services/autopush/commit/aa738816ca3dd7c5ed803cffaa14c7ef8abc9f5f), closes [#535](https://github.com/mozilla-services/autopush/issues/535))
*   fix up AWS conditional binding and assoc. conditions ([9e3fedbe](https://github.com/mozilla-services/autopush/commit/9e3fedbefcfc3b35863020281f4eaadb2453fee2))
*   remove use of buggy moto from websocket/db tests ([07fd0caf](https://github.com/mozilla-services/autopush/commit/07fd0cafe5fd1087173f7894030788d3a41b4e90), closes [#531](https://github.com/mozilla-services/autopush/issues/531))
*   ensure router_type is present in all records ([aeeea3ab](https://github.com/mozilla-services/autopush/commit/aeeea3abf4cd697e6400bbe8dd61c5eb2b3131f9), closes [#526](https://github.com/mozilla-services/autopush/issues/526))



<a name="1.16.0"></a>
## 1.16.0 (2016-07-15)


#### Bug Fixes

*   refactor register uaid lookup to verify proper records ([a01dabd7](https://github.com/mozilla-services/autopush/commit/a01dabd7808f4a050595fe25e274e7808eba2291), closes [#523](https://github.com/mozilla-services/autopush/issues/523))
*   restore pragma line for full coverage ([677e72dd](https://github.com/mozilla-services/autopush/commit/677e72dda1cc6c8c4ee0a0d0103e1011a46e58d4))
*   Invalidate UAIDs that are not lowercase or contain dashes ([265d7689](https://github.com/mozilla-services/autopush/commit/265d7689412afcd90bcf04b805abaea419bea4a7), closes [#519](https://github.com/mozilla-services/autopush/issues/519))
*   log message errors as info instead of debug ([ccc2d685](https://github.com/mozilla-services/autopush/commit/ccc2d6858b27a0f3e542785293fcc57578bf5998), closes [#518](https://github.com/mozilla-services/autopush/issues/518))
*   remove shared file inclusion for tests ([465bcb34](https://github.com/mozilla-services/autopush/commit/465bcb349c301a0f7048c5941042b9716eb0070e), closes [#515](https://github.com/mozilla-services/autopush/issues/515))
*   include webpush handler in endpoint config ([b4493acb](https://github.com/mozilla-services/autopush/commit/b4493acbc58b6c23d4d2ec94ac6d63bf4d0b6911))
*   Elevate GCM reported error states ([04080539](https://github.com/mozilla-services/autopush/commit/040805397c49842cc9b580aa05cd6368790e9319))
*   handle different behavior in rotating table tests at month-end ([19973721](https://github.com/mozilla-services/autopush/commit/199737218444aaf50e9bbacd78e262967fccc734), closes [#502](https://github.com/mozilla-services/autopush/issues/502))
*   remove failing key check from sentry logging ([6c90f8dc](https://github.com/mozilla-services/autopush/commit/6c90f8dcb5641e8f13199bbfaa20edfa66975279))
*   add integration testing and verification of sentry reporting ([ee4e3398](https://github.com/mozilla-services/autopush/commit/ee4e3398eb3d525a54c0199ba93b76358c7fd1ef), closes [#493](https://github.com/mozilla-services/autopush/issues/493))
*   Elevate GCM reported error states ([fb5ae0b3](https://github.com/mozilla-services/autopush/commit/fb5ae0b324678ce2f8ed0a2bc1fac5ac6b588c9e))
*   handle different behavior in rotating table tests at month-end ([bd60b39e](https://github.com/mozilla-services/autopush/commit/bd60b39e3f99cd960f48d5cdb6cad2b58b24241f), closes [#502](https://github.com/mozilla-services/autopush/issues/502))
*   remove failing key check from sentry logging ([3782024b](https://github.com/mozilla-services/autopush/commit/3782024b9de099df6650a776ba8dae6d9dc6379d))
*   add integration testing and verification of sentry reporting ([9c70b88f](https://github.com/mozilla-services/autopush/commit/9c70b88f6c8515ac8f5bfdcc099075e0701123b7), closes [#493](https://github.com/mozilla-services/autopush/issues/493))

#### Test

*   lower time-outs for failed notification checks ([ed7a69f4](https://github.com/mozilla-services/autopush/commit/ed7a69f4e2a87451be52862425a0c5a45e24d0a9))
*   fix/add remaining tests for 100% test coverage ([c505edf7](https://github.com/mozilla-services/autopush/commit/c505edf71d294ea7ed42212503a282fe78b241a9))

#### Breaking Changes

*   add AMI instance ID to the logged information ([058c601b](https://github.com/mozilla-services/autopush/commit/058c601b423e70ec191da35a5251e147aa1c26a8), closes [#483](https://github.com/mozilla-services/autopush/issues/483), breaks [#](https://github.com/mozilla-services/autopush/issues/))
*   add AMI instance ID to the logged information ([663eec02](https://github.com/mozilla-services/autopush/commit/663eec021b41482ea6171582fa35951b92cfdeb6), closes [#483](https://github.com/mozilla-services/autopush/issues/483), breaks [#](https://github.com/mozilla-services/autopush/issues/))

#### Features

*   wait for tables to be active in pre-flight check ([fb143a9b](https://github.com/mozilla-services/autopush/commit/fb143a9b9068a1130607a5894c7e87ade1fbe8bc), closes [#433](https://github.com/mozilla-services/autopush/issues/433))
*   add diagnostic CLI tool for endpoints ([a17679f3](https://github.com/mozilla-services/autopush/commit/a17679f3c9fede9833f451fd910781c924557ad6), closes [#509](https://github.com/mozilla-services/autopush/issues/509))
*   change how bad bridge tokens are handled ([0c73fd0b](https://github.com/mozilla-services/autopush/commit/0c73fd0b39c93af0276df9d215dea2ed2b2d17dd))
*   add metrics to bridge protocols ([e45b82dd](https://github.com/mozilla-services/autopush/commit/e45b82dd995f4dbe28e0b6888bc25404bdf8efc1))
*   add AMI instance ID to the logged information ([058c601b](https://github.com/mozilla-services/autopush/commit/058c601b423e70ec191da35a5251e147aa1c26a8), closes [#483](https://github.com/mozilla-services/autopush/issues/483), breaks [#](https://github.com/mozilla-services/autopush/issues/))
*   refactor webpush endpoint for validation schemas ([c1923e1c](https://github.com/mozilla-services/autopush/commit/c1923e1ca827d919932e48c94d71b3d1ac15899a), closes [#379](https://github.com/mozilla-services/autopush/issues/379))
*   refactor simplepush endpoint for validation schemas ([050d7038](https://github.com/mozilla-services/autopush/commit/050d7038c2ffb3c76dbf25872fc507071ae6e845))
*   Add endpoint to test logging ([824d102d](https://github.com/mozilla-services/autopush/commit/824d102d53dce066a2c6ff49c5b730a2f684840e), closes [#478](https://github.com/mozilla-services/autopush/issues/478))
*   change how bad bridge tokens are handled ([0eb471b6](https://github.com/mozilla-services/autopush/commit/0eb471b69f5af596cf020dd2c52e0657ff5b5f9e))
*   add metrics to bridge protocols ([126203bb](https://github.com/mozilla-services/autopush/commit/126203bb7bd4a161191dc10202249822de404752))
*   add AMI instance ID to the logged information ([663eec02](https://github.com/mozilla-services/autopush/commit/663eec021b41482ea6171582fa35951b92cfdeb6), closes [#483](https://github.com/mozilla-services/autopush/issues/483), breaks [#](https://github.com/mozilla-services/autopush/issues/))
*   refactor webpush endpoint for validation schemas ([f5f366fc](https://github.com/mozilla-services/autopush/commit/f5f366fc95c6bcb4eddb084c3c4eff8a7c5a1612), closes [#379](https://github.com/mozilla-services/autopush/issues/379))
*   refactor simplepush endpoint for validation schemas ([d66102b7](https://github.com/mozilla-services/autopush/commit/d66102b74c22f442ce49ef35c6b2be15a81b5471))
*   Add endpoint to test logging ([0684d898](https://github.com/mozilla-services/autopush/commit/0684d898b0ebdfcf75d10823ea999ee921f141f2), closes [#478](https://github.com/mozilla-services/autopush/issues/478))

#### Chore

*   add python27 dockerfile (#495) ([bfc4f16a](https://github.com/mozilla-services/autopush/commit/bfc4f16a79771c07f42de297d5036b7aa992fb26))
*   add requirements - gnureadline for pypy (#477) ([58f9919d](https://github.com/mozilla-services/autopush/commit/58f9919d032cd94006c0b6b6b06d561d86089589))
*   add default.nix for nix/nixos users ([62454d65](https://github.com/mozilla-services/autopush/commit/62454d65a85466553d76ab6f4ef3e6bdf9671c40))
*   add python27 dockerfile (#495) ([183d2984](https://github.com/mozilla-services/autopush/commit/183d2984c1c45d3ffbb45369395196acf2c991fd))
*   add requirements - gnureadline for pypy (#477) ([d2baf047](https://github.com/mozilla-services/autopush/commit/d2baf04793bdaa62945458ce4c26ae9e7b574cdd))
*   add default.nix for nix/nixos users ([19e939b6](https://github.com/mozilla-services/autopush/commit/19e939b64415c3c0a705d62412ff1c4eac5a0615))
* **Dockerfile:**
  *  die quickly if build command fails (#476) ([1cb329fa](https://github.com/mozilla-services/autopush/commit/1cb329fa99f663b80189ff4eef745faeafdcc9a1))
  *  die quickly if build command fails (#476) ([aecedaf6](https://github.com/mozilla-services/autopush/commit/aecedaf6f8a0256e0fe0058528ed830aa8ab1ef4))



<a name="1.15.0"></a>
## 1.15.0 (2016-05-16)


#### Doc

*   Use shields.io image for code coverage ([4e767a71](https://github.com/mozilla-services/autopush/commit/4e767a71a7315cbff45710cb0c196179348a31d9))

#### Chore

*   update all libs to latest versions and fix jws conflict ([1cbf94f3](https://github.com/mozilla-services/autopush/commit/1cbf94f3168749105d3f0d14c788ca7b2573661c), closes [#453](https://github.com/mozilla-services/autopush/issues/453))

#### Bug Fixes

*   Normalize padding handling for restricted subscriptions ([17e885bf](https://github.com/mozilla-services/autopush/commit/17e885bf7412b7ca333d57081595ad4d6868152c), closes [#466](https://github.com/mozilla-services/autopush/issues/466))
*   Fix logging message inconsistencies ([37d09b30](https://github.com/mozilla-services/autopush/commit/37d09b3007a4060b85999e6863febdc73c7f58cb), closes [#460](https://github.com/mozilla-services/autopush/issues/460))
*   Check connected month bounds for preflight ([63ff016c](https://github.com/mozilla-services/autopush/commit/63ff016c3102e516d1966c964d054ce4ec2b17d1), closes [#461](https://github.com/mozilla-services/autopush/issues/461))
*   Log status_code & errno for all errors ([d2c36fcd](https://github.com/mozilla-services/autopush/commit/d2c36fcdf696bd7706cbfc3853d8a6530736454e), closes [#457](https://github.com/mozilla-services/autopush/issues/457))
*   Strip padding from key content ([ec48a6cc](https://github.com/mozilla-services/autopush/commit/ec48a6cc68bf1a5ff4fb3355bf3651abf958350a), closes [#451](https://github.com/mozilla-services/autopush/issues/451))
*   Correct documents to strongly recommend well formatted UUIDs ([b58e6339](https://github.com/mozilla-services/autopush/commit/b58e6339d506838d253f8c0f6f04027088ebf642), closes [#392](https://github.com/mozilla-services/autopush/issues/392), breaks [#](https://github.com/mozilla-services/autopush/issues/))
*   Use static UAIDs for preflight, clean up after. ([e19329d5](https://github.com/mozilla-services/autopush/commit/e19329d5eb30405be4c852cbcf1e7ea5e1c31ab4), closes [#434](https://github.com/mozilla-services/autopush/issues/434))
*   Canonicalize Base64 URL-encoded values per RFC 7515. ([9406e0d6](https://github.com/mozilla-services/autopush/commit/9406e0d6ca32df9604638b8d1990d7f5c9428c44))

#### Breaking Changes

*   Correct documents to strongly recommend well formatted UUIDs ([b58e6339](https://github.com/mozilla-services/autopush/commit/b58e6339d506838d253f8c0f6f04027088ebf642), closes [#392](https://github.com/mozilla-services/autopush/issues/392), breaks [#](https://github.com/mozilla-services/autopush/issues/))

#### Features

*   use gnureadline instead of readline ([e2a6b727](https://github.com/mozilla-services/autopush/commit/e2a6b7279c85f01b29781bde39a7837a1e868a6a))
*   Add extended err message for old encryption ([a236c90a](https://github.com/mozilla-services/autopush/commit/a236c90aac2d24b15bab42ef00cf8a50a42e3353))
*   Support app server keys via the HTTP interface. ([88b1f037](https://github.com/mozilla-services/autopush/commit/88b1f03741bc776ce750b2f2bece3985f7825f2b), closes [#423](https://github.com/mozilla-services/autopush/issues/423))

#### Refactor

*   Remove duplicate validation logic in the GCM and APNs routers. ([c9fe7627](https://github.com/mozilla-services/autopush/commit/c9fe762772c031336611cffd069033aa51d8807f))



<a name="1.14.2"></a>
## 1.14.2 (2016-04-07)


#### Bug Fixes

*   flatten JWT for logging. ([f56f8f1a](https://github.com/mozilla-services/autopush/commit/f56f8f1a887dd66855f7849f523d59a25f5b7d18))



<a name="1.14.1"></a>
## 1.14.1 (2016-03-28)


#### Chore

*   tag 1.14.1 ([8cf95035](https://github.com/mozilla-services/autopush/commit/8cf950355ee08421cc48aeebaa7d4427864fcb54))

#### Bug Fixes

*   update cffi dep and ensure test reqs matches reqs ([669e1b24](https://github.com/mozilla-services/autopush/commit/669e1b244cf5412df604059da27bdf850446b487))


<a name="1.14.0"></a>
## 1.14.0 (2016-03-28)


#### Chore

*   tag 1.14.0 release ([bcfb4e30](https://github.com/mozilla-services/autopush/commit/bcfb4e301dceae020e12ff0599d805408406640e))
*   add slack travis output ([aa662661](https://github.com/mozilla-services/autopush/commit/aa662661679f16e5d91384dfa66c15ed62bcc0ad))

#### Bug Fixes

*   limit valid months to acceptable range ([a06c5ad6](https://github.com/mozilla-services/autopush/commit/a06c5ad683af9a60438dedec55b23be6e80355ba), closes [#350](https://github.com/mozilla-services/autopush/issues/350))
*   enforce fail.value.message to string ([c3b39161](https://github.com/mozilla-services/autopush/commit/c3b39161cdf2e29c35bacaf1480d6c07ade8633f))
*   fix dockerfile for automated builds ([b4f1dcef](https://github.com/mozilla-services/autopush/commit/b4f1dcef4da88a5f4abb8b74ca1c2e9d08ca11f0), closes [#414](https://github.com/mozilla-services/autopush/issues/414))
*   Allow arbitrary args for options and head functions ([46d2c1dc](https://github.com/mozilla-services/autopush/commit/46d2c1dcd7062b4a3352f98905ddef075f76c1d2))
*   decode and process crypto-key header correctly ([f546ed78](https://github.com/mozilla-services/autopush/commit/f546ed78585976d33534595dafcef401c118ea43), closes [#410](https://github.com/mozilla-services/autopush/issues/410))

#### Features

*   allow logging to batch send to aws firehose ([cad54238](https://github.com/mozilla-services/autopush/commit/cad5423867883f404ec12543c6b139d095aedaa5), closes [#421](https://github.com/mozilla-services/autopush/issues/421))
*   update logging for newstyle twisted and file output ([547eb1ed](https://github.com/mozilla-services/autopush/commit/547eb1edbb62722b7636b1211ecfc405d3263beb), closes [#419](https://github.com/mozilla-services/autopush/issues/419))
*   bump autobahn/twisted reqs to 0.13/16.0 for utf8 fix ([89dc0c28](https://github.com/mozilla-services/autopush/commit/89dc0c28fb261f76d309c57a1d9f06ece1c7072f), closes [#351](https://github.com/mozilla-services/autopush/issues/351))



<a name="1.13.2"></a>
## 1.13.2 (2016-03-13)


#### Features

*   validate v0 tokens more thoroughly ([77373cd6](https://github.com/mozilla-services/autopush/commit/77373cd65d91603e39b80ed52d6312a86779ac75), closes [#406](https://github.com/mozilla-services/autopush/issues/406))

#### Bug Fixes

*   Clear corrupted router records ([5580e0d2](https://github.com/mozilla-services/autopush/commit/5580e0d2e3a99035c899721bf36e6f1018f38e38), closes [#400](https://github.com/mozilla-services/autopush/issues/400))
*   clear only the node_id in the router record ([a1ee817c](https://github.com/mozilla-services/autopush/commit/a1ee817c4cabfc5f5352961bdec5262ece3131a0), closes [#401](https://github.com/mozilla-services/autopush/issues/401))


<a name="1.13.1"></a>
## 1.13.1 (2016-03-10)


#### Test

*   fix timing issue in last connect test ([c4039df1](https://github.com/mozilla-services/autopush/commit/c4039df1e159d17f64a316dc8378a64c458ad7fe))

#### Chore

*   fix changelog and clog for past commit oopsies ([90c3ab16](https://github.com/mozilla-services/autopush/commit/90c3ab16addc150d17a161cf091b8a2ea9239d68))
*   update version for 1.13.1 ([7a960b4c](https://github.com/mozilla-services/autopush/commit/7a960b4ce24e7c9225a053f63a038f3a5c6d28c5))

#### Bug Fixes

*   default api_ver to v0 for message endpoint ([86ba66d4](https://github.com/mozilla-services/autopush/commit/86ba66d46792c8cbd746c706c82390e6823ef686), closes [#395](https://github.com/mozilla-services/autopush/issues/395))


<a name="1.13"></a>
## 1.13 (2016-03-07)


#### Features

*   allow channels to register with public key ([3d15b9bb](https://github.com/mozilla-services/autopush/commit/3d15b9bbc5002d8c6b03b3fd57418aa1892be0e7), closes [#326](https://github.com/mozilla-services/autopush/issues/326))
*   accept nack messages, log code for ack/unreg/nack ([2030a4df](https://github.com/mozilla-services/autopush/commit/2030a4df980a9fc04c7edaae85fb57175510481e), closes [#380](https://github.com/mozilla-services/autopush/issues/380))

#### Bug Fixes

*   send raven calls to event loop ([d35a78d4](https://github.com/mozilla-services/autopush/commit/d35a78d44c0838d2b72492b23031614611e960dd), closes [#387](https://github.com/mozilla-services/autopush/issues/387))
*   capture ValueError for empty notifications arrays ([ce27f1e3](https://github.com/mozilla-services/autopush/commit/ce27f1e383886219710786f9d5233e6e7bc95226), closes [#385](https://github.com/mozilla-services/autopush/issues/385))
*   don't return 503 for disconnected user ([43a2e906](https://github.com/mozilla-services/autopush/commit/43a2e90692e81742afe9a44bf836079bcaf2604d), closes [#378](https://github.com/mozilla-services/autopush/issues/378))
*   force header values to lowercase underscored values ([b4517aeb](https://github.com/mozilla-services/autopush/commit/b4517aeb4c804d0d03063d31dd00ea9db4b39bc1), closes [#373](https://github.com/mozilla-services/autopush/issues/373))
*   change message_type to message_source ([d603902c](https://github.com/mozilla-services/autopush/commit/d603902ce7a01ad140eb69c61dd7935a8370315b))
*   pass TTL Header value to GCM ([c5ae841c](https://github.com/mozilla-services/autopush/commit/c5ae841cbd7f8e31dc72f6f42ae1ffe53d5d4078))

<a name="1.12.1"></a>
### 1.12.1 (2016-02-25)


#### Bug Fixes

*   Normalize encryption headers. ([b9c3cc57](https://github.com/mozilla-services/autopush/commit/b9c3cc571fbdce3c2d748a8ad4efd2431c005bdc))
*   allow stored ttl of None to be treated as 0 ([2b75be5f](https://github.com/mozilla-services/autopush/commit/2b75be5fb79d8bd6dc410cea44b6153ec9446b3a), closes [#366](https://github.com/mozilla-services/autopush/issues/366))
*   silence missing TTL errors from sentry log ([c167ee2f](https://github.com/mozilla-services/autopush/commit/c167ee2fdcceb79a21c47eff0ddc46fe4e0b9e9e))

<a name="1.12.0"></a>
## 1.12.0 (2016-02-23)


#### Doc

*   add text and links for 400:111 errors ([515be293](https://github.com/mozilla-services/autopush/commit/515be2939c12dc5b5720e3fcdb2fd7a0e0d60e6b))
*   update CONTRIBUTING.md doc to match our style ([214e8a77](https://github.com/mozilla-services/autopush/commit/214e8a77c890803846bfc6133dafd2b9e1ae2662))

#### Features

*   upgrade autobahn/twisted to 0.12/15.5 ([47597a0d](https://github.com/mozilla-services/autopush/commit/47597a0da8a401aac38167632d316c48c34c3299), closes [#180](https://github.com/mozilla-services/autopush/issues/180))
*   add user-agent logging to acks ([1dbe3460](https://github.com/mozilla-services/autopush/commit/1dbe3460028ae7980fe5a1722f2499e3428838f3))

#### Bug Fixes

*   allow webpush w/no ttl & cleanup 400 logging ([1f01cd70](https://github.com/mozilla-services/autopush/commit/1f01cd70f52de3c22f74a7389019dfafd1d90ea7), closes [#358](https://github.com/mozilla-services/autopush/issues/358))

#### Chore

*   bring project up to standard guidelines ([c2baf49f](https://github.com/mozilla-services/autopush/commit/c2baf49fd6310dde221151a2d088c6c9f6ca7c9f), closes [#344](https://github.com/mozilla-services/autopush/issues/344))

1.11.0 (2016-02-16)
-------------------

### Features

-   Log notifications out of autopush nodes for data on when they were
    actually delivered to clients. Issue \#331.
-   Added VAPID auth support to incoming Push POSTs. Issue \#325. This
    does not yet use token caches since that will introduce database
    changes as well as impact a fair bit more code.
-   Require TTL header for all incoming subscription updates. Issue
    \#329.
-   Added "Location" header to all successful outbound webpush
    subscription update responses. Issue \#338.
-   Whitelist the "Authorization" header for CORS requests. PR \#341.
-   Add a "WWW-Authenticate" header for 401 responses. PR \#341.

### Bug Fixes

-   Use appropriate 400, 404, 410 status codes for differing message
    endpoint results, rather than always a 404. Issue \#312.
-   Do not send useless 'ver' across GCM bridge. Issue \#323.

### Backwards Incompatibilities

-   The TTL header is now required for all subscription updates.
    Messages without this header will return a 400 error (errno 111).

1.10.1 (2016-02-01)
-------------------

### Bug Fixes

-   Use non-conditional update for save\_messages as put\_item relies on
    a flakey conditional check that doesn't apply in our case. Issue
    \#320.
-   Run looping task call to update message table objects on the
    endpoint as well as the connection node. Issue \#319.

1.10.0 (2016-01-29)
-------------------

### Features

-   Tag logged notifications based on whether they're for a webpush user
    or not. Issue \#315.
-   Add maintenance.py script for use in AWS Lambda. Issue \#254.
-   Add use\_webpush base tag for websocket connections using web\_push.
    Issue \#205.
-   Add log message if routing connection is refused. Issue \#283.

### Bug Fixes

-   Increase the type of connection loss exceptions caught by autopush
    that occur during deploys and node losses. Issue \#306.

1.9.3 (2016-01-23)
------------------

-   Fix issue with users connecting with an invalid UAID that didn't
    exist in the database. Issue \#304.

1.9.2 (2016-01-22)
------------------

### Bug Fixes

-   Reduce new UAID's to a single write, this time for real. Issue
    \#300.

1.9.1 (2016-01-22)
------------------

### Bug Fixes

-   Reduce new UAID's to a single write on connect. Issue \#300.
-   Fixes for GCM JSON encoding rejections and ID assignment. Issue
    \#297.

1.9.0 (2016-01-15)
------------------

### Features

-   Utilize router last\_connect index to track whether a user has
    connected in the current month. Issue \#253.
-   Add message table rotation for webpush users. Issue \#191.
-   Capture Authorization header for endpoint requests for logging.
    Issue \#232.
-   New Bridge HTTP API. Issues \#238, \#250, \#251. In cooperation with
    the GCM client work the HTTP Bridge API has been simplified. The new
    method has been detailed in /api/endpoint.py. In essence: The API is
    now bearer token based, and uses the form
    /v1/{BridgeType}/{BridgeToken}/registration[/{uaid}/[subscription/[{chid}]]]
-   Tag endpoint requests with a unique ID. Issue \#268.
-   Fixed document reference to HTTP API to be a deep link.
-   Pass either Encryption-Key or Crypto-Key per WebPush spec change.
    Issue \#258.
-   Removed refences to obsolete simplepush\_test package.
-   Convert outbound GCM data to base64. This should resolve potential
    transcription issues with binary encoded data going over the bridge.
    Issue \#289.
-   Record Requesting Hostname to metrics. Issue \#228.
-   Add key hash for UAIDs NOTE: enabling this will break all currently
    stored UAID records.

### Bug Fixes

-   Fix bug in GCM router call not getting appropriate params dict.
    Issue \#271.
-   Ensure rotating message table exists on startup. Issue \#266.
-   Fix Running documents to reflect usage of local DynamoDB JAR server.
    Issue \#265.
-   Fixed scope issue around the Bridge API delete functions.
-   Fix db test bug with month addition to properly handle December.
    Issue \#261.
-   Relax endpoint TLS cert requirement for https scheme. Issue \#249.
-   Add endpoint names to the docs. Issue \#223.
-   Moved Obsolete command arguments out of required path, and allow
    tester to ignore local configuration files. Issue \#246

### WebPush

### Configuration Changes

-   It is recommended that the following config options be moved to
    .autopush\_shared.ini --gcm\_enabled --senderid\_list
    --senderid\_expry

### Backwards Incompatibilities

-   The previous Bridge HTTP API has been removed.
-   The Push message update mechanism has been removed. Issue \#279.

### Deprecated

-   The following configuration options have been deprecated and will
    soon be removed: --log\_level --external\_router (replaced by
    --apns\_enabled) --max\_message\_size

1.8.1 (2015-11-16)
------------------

### Features

-   Convert proprietary AUTH to use Bearer Token for client REST
    interfaces. Issue \#238.

### Bug Fixes

### WebPush

### Configuration Changes

-   Please include the new --auth\_key which is the base token set for
    generating bearer tokens. This uses the same format as the
    --crypto\_key, but should be a different value to prevent possible
    key detection. The key can be generated using the same bin/autokey
    tool used to generate the crypto\_key

1.8.0 (2015-11-13)
------------------

### Features

-   Server provided SenderID values for GCM router using clients The GCM
    router will randomly select one of a list of SenderIDs stored in S3
    under the "oms-autopush"/"senderids" key. The values can be loaded
    into S3 either via the S3 console, or by running an instance of
    autopush and passing the values as the "senderid\_list" argument.
    Issue \#185.
-   REST Registration will now return a valid ChannelID if one is not
    specified. Issue \#182.
-   Add hello timeout. Issue \#169.
-   Convert proprietary AUTH to use HAWK for client REST interfaces.
    Issue \#201.
-   Add DELETE /uaid[/chid] functions to client REST interfaces. Issue
    \#183.
-   Add .editorconfig for consistent styling in editors. Issue \#218.
-   Added --human\_logs to display more human friendly logging.
-   If you specify the --s3\_bucket=None, the app will only use local
    memory and will not call out to the S3 repository. It is STRONGLY
    suggested that you specify the full --senderid\_list data set.
-   You may now specify multiple keys for the crypto\_key value. Values
    should be a list ordered from newest to oldest allowed key.

### Bug Fixes

-   Capture all ProvisionedException errors in websocket and endpoint
    correctly. Issue \#175.
-   Clean-up several recent deferToLater calls that didn't have their
    cancelled exceptions ignored. Issue \#208.
-   Fix improper attribute reference in delete call. Issue \#211.
-   Always include TTL header in response to a WebPush notification.
    Issue \#194.
-   Increased unit test coverage due to removal of proprietary AUTH.
-   Fixed issue with local senderid data cache. (discovered while
    debugging.)

### WebPush

### Backwards Incompatibilities

-   Do not specify values for boolean flags.
-   'cors' is now enabled by default. In it's place use --nocors if you
    wish to disable CORS. Please remove "cors" flag from configuration
    files.
-   Do not specify --gcm\_apikey. Instead, store the API key and
    senderid as values in S3. The data may still be written as a JSON
    string such as: ' "\_senderID\_": {"auth": "\_api\_key"}}' activate
    the GCM bridge by specifying --gcm\_enabled.

1.7.2 (2015-10-24)
------------------

### Bug Fixes

-   Set SSL mode properly for release buffers.

1.7.1 (2015-10-23)
------------------

### Bug Fixes

-   Change HOSTNAME env name to not conflict with AWS env. Issue \#198
-   Move endpoint\_\* marks to shared variables.

1.7.0 (2015-10-21)
------------------

### Features

-   Add UDP Wake support. Some devices which use SimplePush routing
    offer a feature to wake on a carrier provided UDP ping. Issue \#106.
-   Provide service environment information to help clients identify the
    service environment, server provides it along with the hello
    message. Issue \#50.
-   Add actionable JSON errors to the Endpoint responses. Issue \#178.

### Bug Fixes

-   Reset UAIDs for clients that change their router type. PR \#167.
-   Respond with status code 413 for payloads that exceed the maximum
    size, 404 for invalid tokens, and 400 for missing encryption
    headers. PR \#170.

### WebPush

-   Add Push message update mechanism. Issue \#141.

1.6.0 (2015-09-14)
------------------

### Bug Fixes

-   log\_exception no longer re-raises the exception, which was causing
    onClose to not return thus letting the connectionCount not be
    decremented.
-   Check for stale connection nodes when routing. Issue \#163.
-   Remove logging of sendClose, as its unactionable noise. Add metric
    for sendClose success. Remove final verifyNuke as its never run in
    the several months it was in, indicating that abortConnection is
    100% effective. Issue \#161.
-   Rename SimplePushServerProtocol to PushServerProtocol. Issue \#117.

### WebPush

-   Add an endpoint for deleting undelivered messages. PR \#131.

1.5.1 (2015-09-02)
------------------

### Bug Fixes

-   Don't require nose to be installed to run.

1.5.0 (2015-09-02)
------------------

### Bug Fixes

-   Don't cancel a deferred that was already called.
-   Restore logging of simplepush successfull/stored delivery based on
    status.
-   Restore updates.handled endpoint timer to track time to deliver.

### Features

-   Memory profile benchmarking on a connection, displays in test
    results. Issue \#142.
-   Refactor of attribute assignment to the Websocket instance to avoid
    memory increases due to Python reallocating the underlying dict
    datastructure. Issue \#149.
-   Add close\_handshake\_timeout option, with default of 0 to let our
    own close timer handle clean-up.
-   Up default close handshake timer to 10 seconds for slower clients.
-   Add channel id logging to endpoint.

1.4.1 (2015-08-31)
------------------

### Bug Fixes

-   Expose Web Push headers for CORS requests. PR \#148.
-   Expose argument for larger websocket message sizes (to fix issue
    \#151) Clients with a large number of channelIDs (50+) can cause the
    initial connection to fail. A proper solution is to modify the
    client to not send ChannelIDs as part of the "hello" message, but
    being able to increase the message size on the server should keep
    the server from dying up front. This fix should only impact clients
    with large numbers of registered channels, notably, devs.

1.4.0 (2015-08-27)
------------------

### Bug Fixes

-   Fix \_notify\_node to not attempt delivering to ourselves at the end
    of the client connection.
-   Remove adaptive ping entirely. Send special close code and drop
    clients that ping more frequently than 55 seconds (approx 1 min).
    This will result in clients that ping too much being turned away for
    awhile, but will alleviate data/battery issues in buggy mobile
    clients. Issue \#103.
-   Store and transmit encrypted Web Push messages as Base64-encoded
    strings. PR \#135.

### Features

-   Add /status HTTP endpoint for autopush. Issue \#136.
-   Log all disconnects, whether they were clean, the code, and the
    reason.
-   Allow encryption headers to be omitted for blank messages. Issue
    \#132.

1.3.3 (2015-08-18)
------------------

-   Handle None values in ack updates.

1.3.2 (2015-08-11)
------------------

### Bug Fixes

-   Fix deferToLater to not call the function if it was cancelled using
    a canceller function.
-   Fix finish\_webpush\_notifications to not immediately call
    process\_notifications as that will be called as needed after ack's
    have been completed.
-   Fix process\_ack to not call process\_notifications when using
    webpush if there are still remaining notifications to ack.

### Features

-   Integrate simplepush\_test smoke-test client with the main autopush
    test-suite into the test-runner. Issue \#119.

1.3.1 (2015-08-04)
------------------

### Bug Fixes

-   Fix RouterException to allow for non-logged responses. Change
    RouterException's to only log actual exceptions that should be
    address in bug-fixes. Issue \#125.

1.3.0 (2015-07-29)
------------------

### Features

-   Add WebPush TTL scheme per spec (as of July 28th 2015). Issue \#56.
-   Add WebPush style data delivery with crypto headers to connected
    clients. Each message is stored independently in a new message
    table, with the version and channel id still required to ack a
    message. The version is a UUID4 hex which is also echo'd back to the
    AppServer as a Location URL per the current WebPush spec (as of July
    28th 2015). Issue \#57.
-   Add Sphinx docs with ReadTheDocs publishing. Issue \#98. This change
    also includes a slight Metrics refactoring with a IMetrics
    interface, and renames MetricSink -\> SinkMetrics for naming
    consistency.

### Bug Fixes

-   Increase test coverage of utils for 100% test coverage.
-   Move all dependencies into requirements.txt and freeze them all
    explicitly.

### Internal

-   Refactor proprietary ping handling for modularized dispatch. Issue
    \#82.

    Major changes

    -   RegistrationHandler endpoint is now the sole method for
        registering for a proprietary wake / transport.
    -   `connect` data from websocket hello is ignored.
    -   Unit Testing has been increased to \~ 100% test coverage.
    -   Proprietary Ping and Bridge terminology has been replaced with
        the terms router\_type / router\_data. Router type being one of
        simplepush / apns / gcm and eventually webpush. Router data is
        an arbitrary JSON value as appropriate for the router type.

    db.py

    -   Removed previous methods (deleteByToken/get\_connection/etc) as
        all the router data is included as a single JSON blob for
        DynamoDB to store.
    -   Change register\_user to use UpdateItem to avoid overwriting
        router data when connecting via websocket.

    endpoint.py

    -   EndpointHandler and RegistrationHandler now both inherit from a
        common baseclass: AutoendpointHandler. This baseclass implements
        OPTIONS/HEAD methods, sets the appropriate CORS headers, and has
        several shared error handlers.
    -   A notification has been standardized into a Notification
        namedtuple.
    -   RegistrationHandler API has been changed to have PUT and POST
        methods.
    -   EndpointHandler has been refactored to use the new Router
        interface.
    -   EndpointHandler now uses a basic HMAC auth scheme, GET/PUT with
        existing UAID's require an appropriate HMAC attached with the
        original derived shared key. (Documented in the
        RegistrationHandler.get method)

    websocket.py

    -   Removed use of `connect` data in hello message as
        RegistrationHandler is now the sole method of registering other
        routers.

    router/interface.py (NEW)

    -   IRouter object that all notification routers must implement.
        This handles verifying router data during registration, and is
        responsible for actual delivery of notifications.
    -   RouterException / RouterResponse objects for returning
        appropriate data during register/route\_notification calls.

    router/apnsrouter.py

    -   Moved from bridge/apns.
    -   Refactored to use RouterException/RouterResponse.

    router/gcm.py

    -   Moved from bridge/gcm.
    -   Refactored to use RouterException/RouterResponse.
    -   Removed internal message retries, now returns a 503 in that case
        for the Application Server to retry delivery.

    router/simple.py

    -   Moved code out from endpoint.py.
    -   Refactored existing simplepush routing scheme to use twisted
        inline deferreds to track the logic with less headaches.

### Backward Incompatibilities

-   `bridge` option is now `external_router`.

1.2.3 (2015-06-02)
------------------

### Features

-   Additional logging/metrics on auto-ping and connection aborting.

1.2.2 (2015-05-27)
------------------

### Features

-   Add additional metrics for writers/readers to indicate what twisted
    is still tracking connection-wise.

### Bug Fixes

-   Correct trap for TCP connection closer

1.2.1 (2015-05-20)
------------------

### Bug Fixes

-   Fix error with blank UAIDs being rejected as "already registered"

1.2.0 (2015-05-19)
------------------

### Features

-   Pong delay can no longer be set, and uses an adaptive value based on
    the last ping to try and accurately compensate for higher latency
    connections. This also removes the min\_ping\_interval option such
    that if a client is pinging too frequently we will instead leave
    space for up to the clients timeout of 10-sec (a hardcoded client
    value).

### Bug Fixes

-   Fix 500 errors in endpoint caused by timeouts when trying to deliver
    to expired nodes in the cluster. Resolves Issue \#75.
-   Add CancelledError trap to all deferreds in websocket.py. Resolves
    Issue \#74.
-   Aggressively delete old TCP connections on device reregistration
    (\#72)

### Backwards Incompatibility

-   Removed min\_ping\_interval config option.
-   Removed pong\_delay config option.

1.1rc2 (2015-05-15)
-------------------

### Features

-   Add structured logging output for the endpoint for additional
    request metadata. Resolves Issue \#67.

### Bug Fixes

-   Fix bug with deferreds not being tracked, causing access to objects
    that were cleaned up. Resolves Issue \#66.
-   kill older, duplicate UAID entries that may still be connected.
-   use Websocket Pings to detect dead connections.

1.0rc1 (2015-04-29)
-------------------

### Features

-   Verify ability to read/write DynamoDB tables on startup. Resolves
    Issue \#46.
-   Send un-acknolwedged direct delivery messages to the router if the
    client is disconnected without ack'ing them. Resolves Issue \#36.
-   Use IProducer to more precisely monitor when the client has drained
    the data to immediately resume sending more data. Resolves Issue
    \#28.
-   Add /status HTTP endpoint for autoendpoint. Resolves Issue \#27.
-   Add example stage/prod config files. Resolves Issue \#22.
-   Switch internal routing from requests to twisted http-client.
    Resolves Issue \#21.
-   Add logging for user-agent to metrics tags. Resolves Issue \#20.
-   Add Datadog stats output. Resolves Issue \#17.
-   Add GCM and APNS Bridges. Resolves Issue \#16.
-   Use eliot structured logging for stdout logging that matches ops
    standard for logging. Resolves Issue \#11.
-   Allow storage/router table names to be configurable. Resolves Issue
    \#4.
-   Added optional CORS headers (use --cors to enable). Resolves Issue
    \#3.
-   Add provisioned error metrics to track when throughput is exceeded
    in AWS DynamoDB. Resolves Issue \#2.
-   Add Sentry support (SENTRY\_DSN must be set in the environment).
    Resolves Issue \#1.

### Bug Fixes

-   Capture and log exceptions in websocket protocol functions.
-   Fix bug with 'settings' in cyclone overriding cyclone's settings.
    Resolves Issue \#13.

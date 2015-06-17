.. _db_module:

:mod:`autopush.db`
------------------

.. automodule:: autopush.db

DynamoDB Table Functions
++++++++++++++++++++++++

.. autofunction:: create_router_table

.. autofunction:: create_storage_table

.. autofunction:: get_router_table

.. autofunction:: get_storage_table

Utility Functions
+++++++++++++++++

.. autofunction:: preflight_check

DynamoDB Table Class Abstractions
+++++++++++++++++++++++++++++++++

.. autoclass:: Storage
    :members:
    :special-members: __init__
    :member-order: bysource

.. autoclass:: Router
    :members:
    :special-members: __init__
    :member-order: bysource

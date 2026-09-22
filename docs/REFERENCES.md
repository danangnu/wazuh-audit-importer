# Primary references consulted

- Existing project schema: 001_create_wazuh_audit_poc.sql supplied earlier in this
  conversation. This importer does not replace/re-run it.
- MariaDB .NET Connector (MySqlConnector recommendation):
  https://mariadb.com/docs/connectors/mariadb-connector-net
- MySqlConnector release history (2.6.2; 2.6.1 security fix noted):
  https://mysqlconnector.net/overview/version-history/
- MySqlConnector connection settings and time handling:
  https://mysqlconnector.net/connection-options/
- MySqlConnector parameterized ADO.NET usage:
  https://mysqlconnector.net/tutorials/basic-api/
- Explicit MySqlCommand.Transaction assignment:
  https://mysqlconnector.net/troubleshooting/transaction-usage/
- MariaDB INSERT ... ON DUPLICATE KEY UPDATE:
  https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/inserting-loading-data/insert-on-duplicate-key-update

The application enforces loopback-only DB access for this pilot. Its use of
SslMode=Preferred is not a verified TLS guarantee and must not be copied as a
production remote-connection policy. A remote collector requires a separately
approved connectivity/TLS design.

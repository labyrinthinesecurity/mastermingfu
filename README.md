#Master Ming Fu

Microsoft released a very useful feature called "Azure Access Management Delegation" (https://learn.microsoft.com/en-us/azure/role-based-access-control/delegate-role-assignments-overview)

If it helps addressing a lot of critical Segregation Of Duties (SOD) limitations with the current RBAC system, some important issues remain.

Master Ming Fu is a script (currently in ALPHA version) that will help spot some of these limitations BEFORE you grant permissions to your delegate(s).

## Running the script

### Pre-requisites

Fill-in 5 environment variables:

- tenant_id
- client_id: a SPN with readonly access to AAD / Entra ID
- client_secret
- scope: (currenlty MAster Ming Fu only supports subscription IDs
- delegate: the principal ID of the delegate which will be permitted to assign roles

### Run

./MingFu.sh

Master MingFu will ask for an Azure condition to test. Just hit return to use the default condtion.

## IAM violations



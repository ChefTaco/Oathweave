import { parseClientPolicies } from './client-policy-schema.js';
export { parseClientPolicies, type ClientPolicy } from './client-policy-schema.js';
// Config is local to this IAM install and takes effect only after a reviewed restart.
export const machineClientPolicies = parseClientPolicies(process.env.IAM_MACHINE_CLIENT_POLICIES);

const mongoose = require("mongoose");

const PermissionSchema = new mongoose.Schema({
  credential_type: { type: String, required: true }, // basePermission or delegatedPermission
  delegation_id: { type: String, unique: true, required: true }, // a unique identifier for the delegation
  employee_number: { type: String, required: true }, // delegated_to // employee_number
  delegated_by: { type: String, required: true }, //delegation_id //issuer id
  delegated_by_employee_number: { type: String, required: true }, // employee_number
  permissions_map: { type: Object, required: true }, // // permission json object
  valid_from: { type: Date , required: true }, // unix timestamp epoch 
  valid_until: { type: Date, required: true }, // unix timestamp epoch
  delegation_proof: { type: String, required: true }, // hash(delegation_id + employee_number + permission_map + secret_key)
  // nonce: { type: String, required: true },
  prover_did: { type: String, required: false },
  revoked: { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model("Permission", PermissionSchema);

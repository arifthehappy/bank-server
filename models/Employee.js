const mongoose = require("mongoose");

const EmployeeSchema = new mongoose.Schema({
  employee_number: { type: String, unique: true, required: true, index: true },
  email: { type: String, required: true },
  full_name: { type: String, required: true },
  dob: { type: String, required: true },
  address: { type: String, required: true },
  blood_group: { type: String, required: true },
  date_of_issue: { type: String, required: true },
  date_of_joining: { type: String, required: true },
  branch_name: { type: String, required: false },
  designation: { type: String, required: true },
  branch_code: { type: String, required: false },
  connection_id: { type: String, required: false },
  prover_did: { type: String, required: false },
  status: { type: String, enum: ["active", "inactive"], default: "active" },
}, { timestamps: true });

module.exports = mongoose.model("Employee", EmployeeSchema);

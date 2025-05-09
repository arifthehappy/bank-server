const express = require("express");
const Employee = require("../models/Employee");
const axios = require("axios");
const Permissions = require("../models/Permissions");
const AGENT_URL = process.env.AGENT_URL || "http://localhost:7001"; // Replace with your agent URL

const router = express.Router();

const api = axios.create({
  baseURL: AGENT_URL
});

// Middleware to check if the user is logged in

// Generate new OOB Invitation
router.get("/connect", async (req, res) => {
  try {
    const response = await api.post(`/out-of-band/create-invitation`, {
        alias: "Bank",
        handshake_protocols: ["https://didcomm.org/connections/1.0"],
        goal_code: "bank",
        goal: "Connect to Bank",
        auto_accept: true
    
        },
      );
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: "Error creating invitation", details: error });
  }
});

// Register a new employee in the database after issuing a credential
// This endpoint is called by the webhook listener when a new employee is registered
// and the credential is issued
router.post("/register", async (req, res) => {
  const data = req.body;

  if(!data || !data.connection_id || !data.by_format || !data.by_format.cred_issue) {
    console.error("Invalid data received for registration");
    return res.status(400).json({ error: "Invalid data received" });
  }
  console.log("Registration request received:", data);
  // Extract the required fields from the request body

  const connection_id = data.connection_id;
  const prover_did = data.by_format.cred_request.indy.prover_did
  const full_name = data.by_format.cred_issue.indy.values.full_name.raw;
  const address = data.by_format.cred_issue.indy.values.address.raw;
  const blood_group = data.by_format.cred_issue.indy.values.blood_group.raw;
  const dob = data.by_format.cred_issue.indy.values.dob.raw;
  const email = data.by_format.cred_issue.indy.values.email.raw;
  const employee_number = data.by_format.cred_issue.indy.values.employee_number.raw;
  const date_of_issue = data.by_format.cred_issue.indy.values.date_of_issue.raw;
  const date_of_joining = data.by_format.cred_issue.indy.values.date_of_joining.raw;
  const branch_name = data.by_format.cred_issue.indy.values.branch_name.raw;
  const designation = data.by_format.cred_issue.indy.values.designation.raw;
  const branch_code = data.by_format.cred_issue.indy.values.branch_code.raw;

  try {
    // // Check if the employee already exists
    // const existingEmployee = await Employee.find
    //     ({ email });
    // if (existingEmployee) {
    //   return res.status(400).json({ error: "Employee already exists" });
    // }

    // Create a new employee record in the database
    const newEmployee = new Employee({
      connection_id,
      prover_did,
      full_name,
      address,
      blood_group,
      dob,
      email,
      employee_number,
      date_of_issue,
      date_of_joining,
      branch_name,
      designation,
      branch_code,
      status: "active"
    });

    await newEmployee.save();
    console.log("Employee registered:", newEmployee);
    res.status(201).json({ message: "Employee registered successfully" });
  } catch (error) {
    console.error("Error registering employee:", error);
    res.status(500).json({ errormessage: "Error registering employee", details: error });
  }
});

// store permissions issued (delegation chain) in the database after issuing a credential 
// This endpoint is called by the webhook listener when a new permission delegation is done
// it will be used to verify the delegation chain 
router.post("/permissions/new", async (req, res) => {
  const data = req.body;
  // console.log("Permission request received:", data);

  if(!data || !data.connection_id || !data.by_format || !data.by_format.cred_issue) {
    console.error("Invalid data received for permissions");
    return res.status(400).json({ error: "Invalid data received" });
  }
  console.log("Permissions delegation request received:", data);
  // Extract the required fields from the request body

  // const connection_id = data.connection_id;
  const prover_did = data.by_format.cred_request.indy.prover_did
  const credential_type = data.by_format.cred_issue.indy.values.credential_type.raw;
  const delegation_id = data.by_format.cred_issue.indy.values.delegation_id.raw;
  const employee_number = data.by_format.cred_issue.indy.values.employee_number.raw;
  const delegated_by = data.by_format.cred_issue.indy.values.delegated_by.raw;
  const delegated_by_employee_number = data.by_format.cred_issue.indy.values.delegated_by_employee_number.raw;
  const permissions_map = data.by_format.cred_issue.indy.values.permissions_map.raw;
  const valid_from = data.by_format.cred_issue.indy.values.valid_from.raw;
  const valid_until = data.by_format.cred_issue.indy.values.valid_until.raw;
  const delegation_proof = data.by_format.cred_issue.indy.values.delegation_proof.raw;
  // const nonce = data.by_format.cred_issue.indy.values.nonce.raw;
  // const revoked = data.by_format.cred_issue.indy.values.revoked.raw;

  try {
    // // Check if the delegation already exists
    // const existingDelegation = await Permissions.find
    //     ({ delegation_id });
    // if (existingDelegation) {
    //   return res.status(400).json({ error: "Delegation already exists" });
    // }

    // change valid_from and valid_until to epoch time
    // const validFromDate = new Date(valid_from);
    // const validUntilDate = new Date(valid_until);
    const valid_from_epoch = Date.parse(valid_from);
    const valid_until_epoch = Date.parse(valid_until);


    // Create a new employee record in the database
    const newPermission = new Permissions({
      credential_type,
      delegation_id,
      employee_number,
      delegated_by,
      delegated_by_employee_number,
      permissions_map,
      valid_from: valid_from_epoch,
      valid_until: valid_until_epoch,
      delegation_proof,
      prover_did,
      revoked: false
    });

    await newPermission.save();
    console.log("Permission registered:", newPermission);
    res.status(201).json({ message: "Permission registered successfully" });
  }
  catch (error) {
    console.error("Error registering permission:", error);
    res.status(500).json({ errormessage: "Error registering permission", details: error });
  }


});

// Login using DID
router.post("/login", async (req, res) => {
  // Check if the request body contains the required fields
  if (!req.body || !req.body.did) {
    console.error("Login request missing DID");
    return res.status(400).json({ error: "DID is required" });
  }
  console.log("Login request received:", req.body);
  // Extract the DID from the request body
  const { did } = req.body;
  const employee = await Employee.findOne({ prover_did:did });

  if (!employee) return res.status(404).json({ error: "User not found" });

  // Check if the employee is active
  if (employee.status === "inactive") {
    return res.status(403).json({ error: "User is inactive" });
  }
  // Request Employee VC Proof
  const proofRequest = {
    auto_verify: true,
    comment: "Requesting Employee VC Proof",
    connection_id: employee.connection_id,
    presentation_request: {
      indy: {
        name: "Employee Verification",
        requested_attributes: {
          "additionalProp1": { 
            name: "employee_number" 
          },
          "additionalProp2": { 
            name: "email" 
          },
          "additionalProp3": { 
            name: "full_name" 
          },
          "additionalProp4": { 
            name: "dob" 
          },
          "additionalProp5": { 
            name: "address" 
          },
          "additionalProp6": { 
            name: "blood_group" 
          },
          "additionalProp7": { 
            name: "date_of_issue" 
          },
          "additionalProp8": { 
            name: "date_of_joining" 
          },
          "additionalProp9": { 
            name: "branch_name" 
          },
          "additionalProp10": { 
            name: "designation" 
          },
          "additionalProp11": { 
            name: "branch_code" 
          }
        },
        requested_predicates: {},
        version: "1.0",
        nonce: "1234567890"
      }
    }
  };

  console.log("Proof request:", proofRequest);

  try {
    const response =   await axios.post("https://w80khfvj-7001.inc1.devtunnels.ms/present-proof-2.0/send-request", proofRequest);
    console.log("Proof request sent; response:", response.data);
    // Handle the response as needed
    res.status(200).json({ message: "Proof request sent. Please verify in your wallet.", data: response.data });
  } catch (error) {
    console.error("Error sending proof request:", error);
    res.status(500).json({ error, message: "Failed to send proof request" });
  }
});

// Get a employee by connection_id
// Fetch user details by connection_id
router.get("/user-details/:connection_id", async (req, res) => {
  const { connection_id } = req.params;

  try {
    // Find the employee by connection_id
    const employee = await Employee.findOne({ connection_id });

    if (!employee) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(employee);
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Failed to fetch user details" });
  }
});

module.exports = router;

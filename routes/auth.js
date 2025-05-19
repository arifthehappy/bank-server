const express = require("express");
const Employee = require("../models/Employee");
const axios = require("axios");
dotenv = require("dotenv");
dotenv.config();

const Permissions = require("../models/Permissions");
const AGENT_URL = process.env.AGENT_URL || "http://localhost:7001"; // Replace with your agent URL

const router = express.Router();

const SECRET_KEY = process.env.SECRET_KEY;
const crypto = require("crypto");
console.log(SECRET_KEY, "SECRET_KEY");
const api = axios.create({
  baseURL: AGENT_URL
});

function verifyDelegationProof(permission, secretKey) {
  console.log("secretKey:", secretKey);
  console.log("Verifying delegation proof for permission:", permission);
  // Recreate the hash: delegation_id + employee_number + permissions_map + secretKey
  const data = `${permission.delegation_id}${permission.employee_number}${permission.permissions_map}${secretKey}`;
  console.log(data, "data");
  const hash = crypto.createHash("sha256").update(data).digest("hex");
  console.log("Recreated hash:", hash);
  console.log("Original delegation proof:", permission.delegation_proof);
  // Compare the recreated hash with the stored delegation_proof
  return hash === permission.delegation_proof;
}

function isValidDateRange(valid_from, valid_until) {
  const now = Date.now();
  console.log("Current time:", now);
  console.log("Valid from:", valid_from);
  console.log("Valid until:", valid_until);
  // Convert valid_from and valid_until to epoch time
  const from = new Date(String(`${valid_from}`)).getTime();
  const until = new Date(String(`${valid_until}`)).getTime();
  console.log("Valid from epoch:", from);
  console.log("Valid until epoch:", until);
  // Check if the current time is within the valid range
  const isValid = now >= from && now <= until;
  console.log("Is valid date range:", isValid);
  return isValid;
}

// Recursive Chain Verification
async function verifyDelegationChain(permission) {
  console.log("Verifying permission:", permission);
  // 1. Check revoked
  if (permission.revoked) return { valid: false, reason: "revoked" };

  // 2. Check validity period
  if (!isValidDateRange(permission.valid_from.toISOString(), permission.valid_until.toISOString())) {
    return { valid: false, reason: "not in validity period" };
  }

  // 3. Check delegation_proof
  if (!verifyDelegationProof(permission, SECRET_KEY)) {
    return { valid: false, reason: "invalid delegation proof" };
  }

  // 4. If basePermission, chain ends here
  if (permission.credential_type === "basePermission") {
    return { valid: true, permission };
  }

  // 5. If delegatedPermission, check the parent in the chain
  if (permission.credential_type === "delegatedPermission") {
    // Find the parent permission by delegated_by
    const parent = await Permissions.findOne({
      delegation_id: permission.delegated_by
    });
    if (!parent) return { valid: false, reason: "parent permission not found" };
    // Recursively verify the parent
    return await verifyDelegationChain(parent);
  }

  return { valid: false, reason: "unknown credential_type" };
}

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
  const delegation_allowed = data.by_format.cred_issue.indy.values.delegation_allowed.raw;
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
      delegation_allowed,
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

// request permissions proof
router.post("/request-permissions-proof", async(req, res)=>{
  const {connection_id} = req.body;

  //build the proof request 
  const proofRequest = {
    auto_verify: true,
    comment: "Requesting Permission Proof",
    connection_id,
    presentation_request: {
      indy: {
        name: "Permission Verification",
        requested_attributes: {
          "additionalProp1": { 
            name: "delegation_id" 
          },
          "additionalProp2": { 
            name: "employee_number" 
          },
          "additionalProp3": { 
            name: "delegated_by" 
          },
          "additionalProp4": { 
            name: "delegated_by_employee_number" 
          },
          "additionalProp5": { 
            name: "permissions_map" 
          },
          "additionalProp6": { 
            name: "valid_from" 
          },
          "additionalProp7": { 
            name: "valid_until" 
          },
          "additionalProp8": { 
            name: "delegation_proof" 
          },
          "additionalProp9": { 
            name: "credential_type" 
          },
          "additionalProp10": { 
            name: "delegation_allowed" 
          }
        },
        requested_predicates: {},
        version: "1.0",
        nonce: "1234567890"
      }
    }
  }

  console.log("Proof request:", proofRequest);

  try {
    const response =   await axios.post("https://w80khfvj-7001.inc1.devtunnels.ms/present-proof-2.0/send-request", proofRequest);
    console.log("Proof request sent; response:", response.data);
    // Handle the response as needed
    res.status(200).json({ message: "Proof request sent. Please verify in your wallet.", data: response.data });
  }
  catch (error) {
    console.error("Error sending proof request:", error);
    res.status(500).json({ error, message: "Failed to send proof request" });
  }

})

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

// fetch permission details by delegation id and verify chain
router.get("/permissions/:delegation_id", async(req, res) =>{
  const { delegation_id } = req.params;
  console.log("Fetching permission details for delegation_id:", delegation_id);
  try {
    const permission = await Permissions.findOne({ delegation_id });
    console.log("Permission found:", permission);
    if (!permission) {
      return res.status(404).json({ error: "Permission not found" });
    }

    // Verify the delegation chain
    const result = await verifyDelegationChain(permission);
    if (!result.valid) {
      console.log("Permission is not valid:", result.reason);
      return res.status(403).json({ error: "Permission is not valid", reason: result.reason });
    }

    // If valid, return the permission details
    console.log("Permission is valid returning:", permission);
    res.status(200).json(permission);
  } catch (error) {
    console.error("Error fetching permission details:", error);
    res.status(500).json({ error: "Failed to fetch and verify permission details" });
  }
})

router.get("/employees", async (req, res) => {
  try {
    const employees = await Employee.find({});
    res.status(200).json(employees);
  } catch (error) {
    console.error("Error fetching employees:", error);
    res.status(500).json({ error: "Failed to fetch employees" });
  }
});

function createDelegationProof(delegationData) {
  // Implement the logic to create a delegation proof for the given delegation data
  const data = `${delegationData.delegation_id}${delegationData.employee_number}${delegationData.permissions_map}${SECRET_KEY}`;
  console.log(data, "data");
  const hash = crypto.createHash("sha256").update(data).digest("hex");
  console.log("Delegation proof hash:", hash);
  // Return the delegation proof
  return hash;
}

// POST api to delegate permissions
router.post("/delegate/:did", async (req, res) => {
  const { did } = req.params;
  console.log("Delegation request received from DID:", did);
  const delegationData = req.body;
  console.log("Delegation data in request:", delegationData);

  // create delegation proof for delegation data
  const delegationProof = await createDelegationProof(delegationData);
  // enter delegation proof in delegation data
  delegationData.delegation_proof = delegationProof;
  console.log("Delegation proof created:", delegationProof);
  // get connection id of employee to send credential from database
  const employee = await Employee.findOne({ employee_number: delegationData.employee_number });
  const selectedConnectionIdSend = employee.connection_id;
  // get cred def id of employee to send credential
  // setting static cred def id for now for permissions should be dynamic in future
  const selectedCredDefIdSend = "VwJVVUv3Vqm8c8FhzTVeea:3:CL:36:permissions30.04.2025"
  // comment to send delegated permission
  const commentSend = "sending delegated permission";

  const attributesArray = Object.entries(delegationData).map(([key, value]) => ({
    name: key,
    value: String(value), // Ensure all values are strings
  }));

  const payloadData = {
      connection_id: selectedConnectionIdSend,
      commentSend,
      credential_preview: {
        "@type": "issue-credential/2.0/credential-preview",
        attributes: attributesArray,
      },
      filter: {
        indy: {
          cred_def_id: selectedCredDefIdSend,
        },
      },
  }

  console.log("Payload data: ",payloadData);
  // console.log("payload attributes: ", payloadData.credential_preview.attributes);
  // res.status(200).json({ message: "dummy Delegation request sent. employee to receive in wallet.", data: payloadData });
  // send credential api to agent
  try{
    const response = await axios.post(`${AGENT_URL}/issue-credential-2.0/send`, payloadData);
    console.log("Credential sent; response:", response.data);
    // Handle the response as needed
    res.status(200).json({ message: "Credential sent. employee to receive in wallet.", data: response.data });
  }
  catch (error) {
    console.error("Error sending credential:", error);
    res.status(500).json({ error, message: "Failed to send credential" });
  }
  
});

const BANK_OWNER_DID = process.env.BANK_OWNER_DID; // Add this to your .env file

// Fetch delegations made by a specific employee
router.get("/delegations/by-me/:employeeNumber", async (req, res) => {
  const { employeeNumber } = req.params;
  try {
    const delegations = await Permissions.find({ delegated_by_employee_number: employeeNumber });
    if (!delegations) {
      return res.status(404).json({ error: "No delegations found for this employee." });
    }
    res.status(200).json(delegations);
  } catch (error) {
    console.error("Error fetching delegations by employee:", error);
    res.status(500).json({ error: "Failed to fetch delegations" });
  }
});

// Revoke a specific delegation
router.post("/delegations/revoke/:delegationId", async (req, res) => {
  const { delegationId } = req.params;
  const { requesterEmployeeNumber, requesterDid } = req.body;

  if (!requesterEmployeeNumber || !requesterDid) {
    return res.status(400).json({ error: "Requester employee number and DID are required." });
  }

  if (!BANK_OWNER_DID) {
    console.error("BANK_OWNER_DID is not set in environment variables.");
    return res.status(500).json({ error: "Server configuration error." });
  }

  try {
    const delegation = await Permissions.findOne({ delegation_id: delegationId });
    if (!delegation) {
      return res.status(404).json({ error: "Delegation not found." });
    }

    // Authorization check
    const isOwner = requesterDid === BANK_OWNER_DID;
    const isDelegator = requesterEmployeeNumber === delegation.delegated_by_employee_number;

    if (!isOwner && !isDelegator) {
      return res.status(403).json({ error: "Unauthorized to revoke this delegation." });
    }

    if (delegation.revoked) {
      return res.status(400).json({ message: "Delegation is already revoked." });
    }
    delegation.revoked = true;
    await delegation.save();
    res.status(200).json({ message: "Delegation revoked successfully.", delegation });
  } catch (error) {
    console.error("Error revoking delegation:", error);
    res.status(500).json({ error: "Failed to revoke delegation" });
  }
});

module.exports = router;

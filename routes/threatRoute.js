

import express from "express"
import upload from "../middleware/upload.js";

import {
    threatController
} from "../controller/threatController.js"

const router = express.Router()

// Threat Intelligence Scanning
// This route handles POST requests to the /threat endpoint
// It uses the threatController to process the request
// The threatController is expected to handle the logic for threat intelligence scanning
router.post("/", threatController)



// Additional routes can be added here as needed
// Export the router to be used in the main app
// This allows the main app to use this router for handling web-related routes
export default router
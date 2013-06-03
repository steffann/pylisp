Version 0.3
===========
Released: 2013-01-23 20:14:46 +0100

 * Add changelog for 0.3
 * We can do Map-Registers and process Map-Notifies!
 * Add unicode output for LCAF addresses
 * And we have a semi-working lispd again!
 * Fix network arguments
 * Starting on handlers
 * Cleaning up some old garbage
 * The basics for a new attemts at a lispd
 * Split resolve in resolve_path and resolve
 * Add a bit of docs
 * Clean up imports
 * Fix class structure
 * New simple node types
 * Fixes for IPy to ipaddress migration
 * New LISP EID tree code
 * Migrate from IPy to ipaddress (which is part of the standard library since Py3.3)
 * Better descriptions about action codes
 * starting a new lispd
 * Split of representation __repr__
 * Nicer threading
 * Experimental lispd stuff
 * Cleaner config
 * Store reserved bits for all packet types
 * Trying to implement a Map-Server
 * Add support for NATT in Map-Register and make the Map-Register-Record a separate class for clarity
 * Better exception reporting
 * Test script for map register
 * Fix import
 * Testing with bad signature handling because of unexpected bits being set to 1
 * Move to integrated clone of IPy, the original has annoying bugs
 * Handle LCAF addresses in Locator Records
 * Recursive LCAF address extraction
 * Fix error message for bad authentication data
 * Add a get_addresses() method to aid other code in validating content
 * LISP ControlMessage is a ProtocolElement
 * Add validation
 * Store the filename after we confirm parsing the content
 * Add TODO comments to mark work items
 * Add changelog for 0.2
 * This is a ProtocolElement, not a Protocol (it has no header-type and no next-header fields)

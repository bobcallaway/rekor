// Code generated by go-swagger; DO NOT EDIT.

// /*
// Copyright The Rekor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */
//

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "consumes": [
    "application/json",
    "application/xml",
    "application/yaml"
  ],
  "produces": [
    "application/json;q=1",
    "application/xml",
    "application/yaml"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Rekor is a cryptographically secure, immutable transparency log for signed software releases.",
    "title": "Rekor",
    "version": "0.0.1"
  },
  "paths": {
    "/api/v1/log": {
      "get": {
        "description": "Returns the current root hash and size of the merkle tree used to store the log entries.",
        "tags": [
          "tlog"
        ],
        "summary": "Get information about the current state of the transparency log",
        "operationId": "getLogInfo",
        "responses": {
          "200": {
            "description": "A JSON object with the root hash and tree size as properties",
            "schema": {
              "$ref": "#/definitions/LogInfo"
            }
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/log/entries": {
      "get": {
        "tags": [
          "entries"
        ],
        "summary": "Retrieves an entry from the transparency log (if it exists) by index",
        "operationId": "getLogEntryByIndex",
        "parameters": [
          {
            "type": "integer",
            "description": "specifies the index of the entry in the transparency log to be retrieved",
            "name": "logIndex",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "the entry in the transparency log requested",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            }
          },
          "404": {
            "$ref": "#/responses/NotFound"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      },
      "post": {
        "description": "Creates an entry in the transparency log for a detached signature, public key, and content. Items can be included in the request or fetched by the server when URLs are specified.\n",
        "tags": [
          "entries"
        ],
        "summary": "Creates an entry in the transparency log",
        "operationId": "createLogEntry",
        "parameters": [
          {
            "name": "proposedEntry",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/ProposedEntry"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Returns the entry created in the transparency log",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            },
            "headers": {
              "ETag": {
                "type": "string",
                "description": "UUID of log entry"
              },
              "Location": {
                "type": "string",
                "format": "uri",
                "description": "URI location of log entry"
              }
            }
          },
          "400": {
            "$ref": "#/responses/BadContent"
          },
          "409": {
            "$ref": "#/responses/Conflict"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/log/entries/retrieve": {
      "post": {
        "tags": [
          "entries"
        ],
        "summary": "Searches transparency log for one or more log entries",
        "operationId": "searchLogQuery",
        "parameters": [
          {
            "name": "entry",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/SearchLogQuery"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Returns zero or more entries from the transparency log, according to how many were included in request query",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/LogEntry"
              }
            }
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/log/entries/{entryUUID}": {
      "get": {
        "tags": [
          "entries"
        ],
        "summary": "Retrieves an entry from the transparency log (if it exists) by UUID",
        "operationId": "getLogEntryByUUID",
        "parameters": [
          {
            "type": "string",
            "description": "the UUID of the entry to be retrieved from the log. The UUID is also the merkle tree hash of the entry.",
            "name": "entryUUID",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "the entry in the transparency log requested",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            }
          },
          "404": {
            "$ref": "#/responses/NotFound"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/log/entries/{entryUUID}/proof": {
      "get": {
        "description": "Returns root hash, tree size, and a list of hashes that can be used to calculate proof of an entry being included in the transparency log",
        "tags": [
          "entries"
        ],
        "summary": "Get information required to generate an inclusion proof for a specified entry in the transparency log",
        "operationId": "getLogEntryProof",
        "parameters": [
          {
            "type": "string",
            "description": "the UUID of the entry for which the inclusion proof information should be returned",
            "name": "entryUUID",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Information needed for a client to compute the inclusion proof",
            "schema": {
              "$ref": "#/definitions/InclusionProof"
            }
          },
          "404": {
            "$ref": "#/responses/NotFound"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    },
    "/api/v1/log/proof": {
      "get": {
        "description": "Returns a list of hashes for specified tree sizes that can be used to confirm the consistency of the transparency log",
        "tags": [
          "tlog"
        ],
        "summary": "Get information required to generate a consistency proof for the transparency log",
        "operationId": "getLogProof",
        "parameters": [
          {
            "minimum": 1,
            "type": "integer",
            "default": 1,
            "description": "The size of the tree that you wish to prove consistency from (1 means the beginning of the log) Defaults to 1 if not specified\n",
            "name": "firstSize",
            "in": "query"
          },
          {
            "minimum": 1,
            "type": "integer",
            "description": "The size of the tree that you wish to prove consistency to",
            "name": "lastSize",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "All hashes required to compute the consistency proof",
            "schema": {
              "$ref": "#/definitions/ConsistencyProof"
            }
          },
          "400": {
            "$ref": "#/responses/BadContent"
          },
          "default": {
            "$ref": "#/responses/InternalServerError"
          }
        }
      }
    }
  },
  "definitions": {
    "ConsistencyProof": {
      "type": "object",
      "required": [
        "rootHash",
        "hashes"
      ],
      "properties": {
        "hashes": {
          "type": "array",
          "items": {
            "description": "SHA256 hash value expressed in hexadecimal format",
            "type": "string",
            "pattern": "^[0-9a-fA-F]{64}$"
          }
        },
        "rootHash": {
          "description": "The hash value stored at the root of the merkle tree at time the proof was generated",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        }
      }
    },
    "Error": {
      "type": "object",
      "required": [
        "type",
        "title",
        "status"
      ],
      "properties": {
        "detail": {
          "type": "string"
        },
        "status": {
          "type": "integer"
        },
        "title": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      }
    },
    "InclusionProof": {
      "type": "object",
      "required": [
        "logIndex",
        "rootHash",
        "treeSize",
        "hashes"
      ],
      "properties": {
        "hashes": {
          "description": "A list of hashes required to compute the inclusion proof, sorted in order from leaf to root",
          "type": "array",
          "items": {
            "description": "SHA256 hash value expressed in hexadecimal format",
            "type": "string",
            "pattern": "^[0-9a-fA-F]{64}$"
          }
        },
        "logIndex": {
          "description": "The index of the entry in the transparency log",
          "type": "integer"
        },
        "rootHash": {
          "description": "The hash value stored at the root of the merkle tree at the time the proof was generated",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        },
        "treeSize": {
          "description": "The size of the merkle tree at the time the inclusion proof was generated",
          "type": "integer",
          "minimum": 1
        }
      }
    },
    "LogEntry": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "required": [
          "body"
        ],
        "properties": {
          "body": {
            "type": "object",
            "additionalProperties": true
          },
          "logIndex": {
            "type": "integer"
          }
        }
      }
    },
    "LogInfo": {
      "type": "object",
      "required": [
        "rootHash",
        "treeSize"
      ],
      "properties": {
        "rootHash": {
          "description": "The current hash value stored at the root of the merkle tree",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        },
        "treeSize": {
          "description": "The current number of nodes in the merkle tree",
          "type": "integer",
          "minimum": 1
        }
      }
    },
    "ProposedEntry": {
      "type": "object",
      "required": [
        "kind"
      ],
      "properties": {
        "kind": {
          "type": "string"
        }
      },
      "discriminator": "kind"
    },
    "SearchLogQuery": {
      "type": "object",
      "properties": {
        "entries": {
          "type": "array",
          "items": {
            "minItems": 1,
            "$ref": "#/definitions/ProposedEntry"
          }
        },
        "entryUUIDs": {
          "type": "array",
          "items": {
            "type": "string",
            "minItems": 1
          }
        },
        "logIndexes": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "integer"
          }
        }
      }
    },
    "rekord": {
      "description": "Rekord object",
      "type": "object",
      "allOf": [
        {
          "$ref": "#/definitions/ProposedEntry"
        },
        {
          "required": [
            "apiVersion",
            "spec"
          ],
          "properties": {
            "apiVersion": {
              "type": "string",
              "pattern": "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            },
            "spec": {
              "type": "object",
              "$ref": "pkg/types/rekord/rekord_schema.json"
            }
          },
          "additionalProperties": false
        }
      ]
    }
  },
  "responses": {
    "BadContent": {
      "description": "The content supplied to the server was invalid",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "Conflict": {
      "description": "The request conflicts with the current state of the transparency log",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "InternalServerError": {
      "description": "There was an internal error in the server while processing the request",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "NotFound": {
      "description": "The content requested could not be found",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "consumes": [
    "application/json",
    "application/xml",
    "application/yaml"
  ],
  "produces": [
    "application/json;q=1",
    "application/xml",
    "application/yaml"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Rekor is a cryptographically secure, immutable transparency log for signed software releases.",
    "title": "Rekor",
    "version": "0.0.1"
  },
  "paths": {
    "/api/v1/log": {
      "get": {
        "description": "Returns the current root hash and size of the merkle tree used to store the log entries.",
        "tags": [
          "tlog"
        ],
        "summary": "Get information about the current state of the transparency log",
        "operationId": "getLogInfo",
        "responses": {
          "200": {
            "description": "A JSON object with the root hash and tree size as properties",
            "schema": {
              "$ref": "#/definitions/LogInfo"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/log/entries": {
      "get": {
        "tags": [
          "entries"
        ],
        "summary": "Retrieves an entry from the transparency log (if it exists) by index",
        "operationId": "getLogEntryByIndex",
        "parameters": [
          {
            "minimum": 0,
            "type": "integer",
            "description": "specifies the index of the entry in the transparency log to be retrieved",
            "name": "logIndex",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "the entry in the transparency log requested",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            }
          },
          "404": {
            "description": "The content requested could not be found",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      },
      "post": {
        "description": "Creates an entry in the transparency log for a detached signature, public key, and content. Items can be included in the request or fetched by the server when URLs are specified.\n",
        "tags": [
          "entries"
        ],
        "summary": "Creates an entry in the transparency log",
        "operationId": "createLogEntry",
        "parameters": [
          {
            "name": "proposedEntry",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/ProposedEntry"
            }
          }
        ],
        "responses": {
          "201": {
            "description": "Returns the entry created in the transparency log",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            },
            "headers": {
              "ETag": {
                "type": "string",
                "description": "UUID of log entry"
              },
              "Location": {
                "type": "string",
                "format": "uri",
                "description": "URI location of log entry"
              }
            }
          },
          "400": {
            "description": "The content supplied to the server was invalid",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "409": {
            "description": "The request conflicts with the current state of the transparency log",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/log/entries/retrieve": {
      "post": {
        "tags": [
          "entries"
        ],
        "summary": "Searches transparency log for one or more log entries",
        "operationId": "searchLogQuery",
        "parameters": [
          {
            "name": "entry",
            "in": "body",
            "required": true,
            "schema": {
              "$ref": "#/definitions/SearchLogQuery"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Returns zero or more entries from the transparency log, according to how many were included in request query",
            "schema": {
              "type": "array",
              "items": {
                "$ref": "#/definitions/LogEntry"
              }
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/log/entries/{entryUUID}": {
      "get": {
        "tags": [
          "entries"
        ],
        "summary": "Retrieves an entry from the transparency log (if it exists) by UUID",
        "operationId": "getLogEntryByUUID",
        "parameters": [
          {
            "type": "string",
            "description": "the UUID of the entry to be retrieved from the log. The UUID is also the merkle tree hash of the entry.",
            "name": "entryUUID",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "the entry in the transparency log requested",
            "schema": {
              "$ref": "#/definitions/LogEntry"
            }
          },
          "404": {
            "description": "The content requested could not be found",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/log/entries/{entryUUID}/proof": {
      "get": {
        "description": "Returns root hash, tree size, and a list of hashes that can be used to calculate proof of an entry being included in the transparency log",
        "tags": [
          "entries"
        ],
        "summary": "Get information required to generate an inclusion proof for a specified entry in the transparency log",
        "operationId": "getLogEntryProof",
        "parameters": [
          {
            "type": "string",
            "description": "the UUID of the entry for which the inclusion proof information should be returned",
            "name": "entryUUID",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "Information needed for a client to compute the inclusion proof",
            "schema": {
              "$ref": "#/definitions/InclusionProof"
            }
          },
          "404": {
            "description": "The content requested could not be found",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    },
    "/api/v1/log/proof": {
      "get": {
        "description": "Returns a list of hashes for specified tree sizes that can be used to confirm the consistency of the transparency log",
        "tags": [
          "tlog"
        ],
        "summary": "Get information required to generate a consistency proof for the transparency log",
        "operationId": "getLogProof",
        "parameters": [
          {
            "minimum": 1,
            "type": "integer",
            "default": 1,
            "description": "The size of the tree that you wish to prove consistency from (1 means the beginning of the log) Defaults to 1 if not specified\n",
            "name": "firstSize",
            "in": "query"
          },
          {
            "minimum": 1,
            "type": "integer",
            "description": "The size of the tree that you wish to prove consistency to",
            "name": "lastSize",
            "in": "query",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "All hashes required to compute the consistency proof",
            "schema": {
              "$ref": "#/definitions/ConsistencyProof"
            }
          },
          "400": {
            "description": "The content supplied to the server was invalid",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          },
          "default": {
            "description": "There was an internal error in the server while processing the request",
            "schema": {
              "$ref": "#/definitions/Error"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "ConsistencyProof": {
      "type": "object",
      "required": [
        "rootHash",
        "hashes"
      ],
      "properties": {
        "hashes": {
          "type": "array",
          "items": {
            "description": "SHA256 hash value expressed in hexadecimal format",
            "type": "string",
            "pattern": "^[0-9a-fA-F]{64}$"
          }
        },
        "rootHash": {
          "description": "The hash value stored at the root of the merkle tree at time the proof was generated",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        }
      }
    },
    "Error": {
      "type": "object",
      "required": [
        "type",
        "title",
        "status"
      ],
      "properties": {
        "detail": {
          "type": "string"
        },
        "status": {
          "type": "integer"
        },
        "title": {
          "type": "string"
        },
        "type": {
          "type": "string"
        }
      }
    },
    "InclusionProof": {
      "type": "object",
      "required": [
        "logIndex",
        "rootHash",
        "treeSize",
        "hashes"
      ],
      "properties": {
        "hashes": {
          "description": "A list of hashes required to compute the inclusion proof, sorted in order from leaf to root",
          "type": "array",
          "items": {
            "description": "SHA256 hash value expressed in hexadecimal format",
            "type": "string",
            "pattern": "^[0-9a-fA-F]{64}$"
          }
        },
        "logIndex": {
          "description": "The index of the entry in the transparency log",
          "type": "integer",
          "minimum": 0
        },
        "rootHash": {
          "description": "The hash value stored at the root of the merkle tree at the time the proof was generated",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        },
        "treeSize": {
          "description": "The size of the merkle tree at the time the inclusion proof was generated",
          "type": "integer",
          "minimum": 1
        }
      }
    },
    "LogEntry": {
      "type": "object",
      "additionalProperties": {
        "$ref": "#/definitions/LogEntryAnon"
      }
    },
    "LogEntryAnon": {
      "type": "object",
      "required": [
        "body"
      ],
      "properties": {
        "body": {
          "type": "object",
          "additionalProperties": true
        },
        "logIndex": {
          "type": "integer",
          "minimum": 0
        }
      }
    },
    "LogInfo": {
      "type": "object",
      "required": [
        "rootHash",
        "treeSize"
      ],
      "properties": {
        "rootHash": {
          "description": "The current hash value stored at the root of the merkle tree",
          "type": "string",
          "pattern": "^[0-9a-fA-F]{64}$"
        },
        "treeSize": {
          "description": "The current number of nodes in the merkle tree",
          "type": "integer",
          "minimum": 1
        }
      }
    },
    "ProposedEntry": {
      "type": "object",
      "required": [
        "kind"
      ],
      "properties": {
        "kind": {
          "type": "string"
        }
      },
      "discriminator": "kind"
    },
    "RekordV001SchemaData": {
      "description": "Information about the content associated with the entry",
      "type": "object",
      "oneOf": [
        {
          "required": [
            "hash",
            "url"
          ]
        },
        {
          "required": [
            "content"
          ]
        }
      ],
      "properties": {
        "content": {
          "description": "Specifies the content inline within the document",
          "type": "string",
          "format": "byte"
        },
        "hash": {
          "description": "Specifies the hash algorithm and value for the content",
          "type": "object",
          "required": [
            "algorithm",
            "value"
          ],
          "properties": {
            "algorithm": {
              "description": "The hashing function used to compute the hash value",
              "type": "string",
              "enum": [
                "sha256"
              ]
            },
            "value": {
              "description": "The hash value for the content",
              "type": "string"
            }
          }
        },
        "url": {
          "description": "Specifies the location of the content; if this is specified, a hash value must also be provided",
          "type": "string",
          "format": "uri"
        }
      }
    },
    "RekordV001SchemaDataHash": {
      "description": "Specifies the hash algorithm and value for the content",
      "type": "object",
      "required": [
        "algorithm",
        "value"
      ],
      "properties": {
        "algorithm": {
          "description": "The hashing function used to compute the hash value",
          "type": "string",
          "enum": [
            "sha256"
          ]
        },
        "value": {
          "description": "The hash value for the content",
          "type": "string"
        }
      }
    },
    "RekordV001SchemaSignature": {
      "description": "Information about the detached signature associated with the entry",
      "type": "object",
      "oneOf": [
        {
          "required": [
            "format",
            "publicKey",
            "url"
          ]
        },
        {
          "required": [
            "format",
            "publicKey",
            "content"
          ]
        }
      ],
      "properties": {
        "content": {
          "description": "Specifies the content of the signature inline within the document",
          "type": "string",
          "format": "byte"
        },
        "format": {
          "description": "Specifies the format of the signature",
          "type": "string",
          "enum": [
            "pgp"
          ]
        },
        "publicKey": {
          "description": "The public key that can verify the signature",
          "type": "object",
          "oneOf": [
            {
              "required": [
                "url"
              ]
            },
            {
              "required": [
                "content"
              ]
            }
          ],
          "properties": {
            "content": {
              "description": "Specifies the content of the public key inline within the document",
              "type": "string",
              "format": "byte"
            },
            "url": {
              "description": "Specifies the location of the public key",
              "type": "string",
              "format": "uri"
            }
          }
        },
        "url": {
          "description": "Specifies the location of the signature",
          "type": "string",
          "format": "uri"
        }
      }
    },
    "RekordV001SchemaSignaturePublicKey": {
      "description": "The public key that can verify the signature",
      "type": "object",
      "oneOf": [
        {
          "required": [
            "url"
          ]
        },
        {
          "required": [
            "content"
          ]
        }
      ],
      "properties": {
        "content": {
          "description": "Specifies the content of the public key inline within the document",
          "type": "string",
          "format": "byte"
        },
        "url": {
          "description": "Specifies the location of the public key",
          "type": "string",
          "format": "uri"
        }
      }
    },
    "SearchLogQuery": {
      "type": "object",
      "properties": {
        "entries": {
          "type": "array",
          "items": {
            "$ref": "#/definitions/ProposedEntry"
          }
        },
        "entryUUIDs": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "logIndexes": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "integer",
            "minimum": 0
          }
        }
      }
    },
    "rekord": {
      "description": "Rekord object",
      "type": "object",
      "allOf": [
        {
          "$ref": "#/definitions/ProposedEntry"
        },
        {
          "required": [
            "apiVersion",
            "spec"
          ],
          "properties": {
            "apiVersion": {
              "type": "string",
              "pattern": "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)(?:-((?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\\.(?:0|[1-9]\\d*|\\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\\+([0-9a-zA-Z-]+(?:\\.[0-9a-zA-Z-]+)*))?$"
            },
            "spec": {
              "$ref": "#/definitions/rekordSchema"
            }
          },
          "additionalProperties": false
        }
      ]
    },
    "rekordSchema": {
      "description": "Schema for Rekord objects",
      "type": "object",
      "title": "Rekor Schema",
      "oneOf": [
        {
          "$ref": "#/definitions/rekordV001Schema"
        }
      ],
      "$schema": "http://json-schema.org/draft-07/schema",
      "$id": "http://rekor.dev/types/rekord/rekord_schema.json"
    },
    "rekordV001Schema": {
      "description": "Schema for Rekord object",
      "type": "object",
      "title": "Rekor v0.0.1 Schema",
      "required": [
        "signature",
        "data"
      ],
      "properties": {
        "data": {
          "description": "Information about the content associated with the entry",
          "type": "object",
          "oneOf": [
            {
              "required": [
                "hash",
                "url"
              ]
            },
            {
              "required": [
                "content"
              ]
            }
          ],
          "properties": {
            "content": {
              "description": "Specifies the content inline within the document",
              "type": "string",
              "format": "byte"
            },
            "hash": {
              "description": "Specifies the hash algorithm and value for the content",
              "type": "object",
              "required": [
                "algorithm",
                "value"
              ],
              "properties": {
                "algorithm": {
                  "description": "The hashing function used to compute the hash value",
                  "type": "string",
                  "enum": [
                    "sha256"
                  ]
                },
                "value": {
                  "description": "The hash value for the content",
                  "type": "string"
                }
              }
            },
            "url": {
              "description": "Specifies the location of the content; if this is specified, a hash value must also be provided",
              "type": "string",
              "format": "uri"
            }
          }
        },
        "extraData": {
          "description": "Arbitrary content to be included in the verifiable entry in the transparency log",
          "type": "object",
          "additionalProperties": true
        },
        "signature": {
          "description": "Information about the detached signature associated with the entry",
          "type": "object",
          "oneOf": [
            {
              "required": [
                "format",
                "publicKey",
                "url"
              ]
            },
            {
              "required": [
                "format",
                "publicKey",
                "content"
              ]
            }
          ],
          "properties": {
            "content": {
              "description": "Specifies the content of the signature inline within the document",
              "type": "string",
              "format": "byte"
            },
            "format": {
              "description": "Specifies the format of the signature",
              "type": "string",
              "enum": [
                "pgp"
              ]
            },
            "publicKey": {
              "description": "The public key that can verify the signature",
              "type": "object",
              "oneOf": [
                {
                  "required": [
                    "url"
                  ]
                },
                {
                  "required": [
                    "content"
                  ]
                }
              ],
              "properties": {
                "content": {
                  "description": "Specifies the content of the public key inline within the document",
                  "type": "string",
                  "format": "byte"
                },
                "url": {
                  "description": "Specifies the location of the public key",
                  "type": "string",
                  "format": "uri"
                }
              }
            },
            "url": {
              "description": "Specifies the location of the signature",
              "type": "string",
              "format": "uri"
            }
          }
        }
      },
      "$schema": "http://json-schema.org/draft-07/schema",
      "$id": "http://rekor.dev/types/rekord/rekord_v0_0_1_schema.json"
    }
  },
  "responses": {
    "BadContent": {
      "description": "The content supplied to the server was invalid",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "Conflict": {
      "description": "The request conflicts with the current state of the transparency log",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "InternalServerError": {
      "description": "There was an internal error in the server while processing the request",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    },
    "NotFound": {
      "description": "The content requested could not be found",
      "schema": {
        "$ref": "#/definitions/Error"
      }
    }
  }
}`))
}

const express = require("express");
const app = express();
const mysql = require("mysql2");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const corsOptions = {
  //this allows follwing mentioned url(here the client) to have access for the server
  origin: ["http://localhost:5173"], // React frontend URL
};
//  (this allows your React app to access the backend)
app.use(cors(corsOptions));

// Middleware to parse JSON
app.use(express.json());
//---------------------------------------------------------------
//this is to make sql connection with the database
const db = mysql.createConnection({
  host: "sql12.freesqldatabase.com", // Remote host address
  port: 3306, // MySQL default port
  user: "sql12752216", // Provided database username
  password: "p2yvVtN7CA", // Provided database password
  database: "sql12752216", // Provided database name
});
// Check database connection
db.connect((err) => {
  if (err) {
    console.log("Error connecting to the database:", err);
  } else {
    console.log("Connected to the database!");
  }
});
//------------------------------------------------
//------------------------------------------------
//
//------------------------------------------------
//register router
app.post("/register", (req, res) => {
  const { username, password, name, email } = req.body; // we get the username and password from the submitted form

  // Step 1: Check if username already exists
  db.query(
    "SELECT * FROM user WHERE username = ?",
    [username],
    (err, existingUser) => {
      if (err) {
        console.error("Error executing the query:", err);
        return res.status(500).send("Database error");
      }

      // if there is a row, it means there is a user with the same username
      if (existingUser.length > 0) {
        console.log("User already exist!!!!!!!!!!!", existingUser);
        return res.status(400).json({ message: "Username already taken" });
      }

      // Step 2: Hash the password and insert the new user into the DB
      bcrypt.hash(password, 10, (err, hash_password) => {
        if (err) {
          console.error("Error hashing password:", err);
          return res.status(500).send("Error hashing password");
        }

        const query =
          "INSERT INTO user (username, password,name,email) VALUES (?, ?,?,?)";
        const values = [username, hash_password, name, email];

        // Insert the new user
        db.query(query, values, (err, result) => {
          if (err) {
            console.error("Error executing the insert query:", err);
            return res.status(500).send("Database error");
          }

          console.log("Data inserted successfully:", result);

          // Step 3: Fetch the user data to send back to the client
          db.query(
            "SELECT * FROM user WHERE username = ?",
            [username],
            (err, userResults) => {
              if (err) {
                console.error("Error fetching user data:", err);
                return res.status(500).send("Database error");
              }

              if (userResults.length === 0) {
                return res.status(404).send("User not found");
              }

              const user = userResults[0];
              console.log(user);

              // Step 4: Compare the passwords directly (use bcrypt in production)
              bcrypt.compare(password, user.password, (err, isMatch) => {
                if (err) {
                  console.error("Error comparing passwords:", err);
                  return res.status(500).send("Error comparing passwords");
                }

                if (!isMatch) {
                  return res
                    .status(401)
                    .send("Invalid password in case of register");
                }

                // Step 5: Create JWT token
                const token = jwt.sign(
                  { id: user.id, role: user.role },
                  "percyjackson", //secret key
                  { expiresIn: "1h" }
                );

                res.json({ token });
              });
            }
          );
        });
      });
    }
  );
});

//----------------------------------------------------------------
//login router
app.post("/login", (req, res) => {
  const { username, password } = req.body; // Get username and password from the request body

  // Check if the user exists in the database
  db.query(
    "SELECT * FROM user WHERE username = ?",
    [username],
    (err, results) => {
      if (err) {
        //checks if the array response fron database is alright
        return res.status(500).send("Database error");
      }

      if (results.length === 0) {
        //if we get nothing in array(array lenght is zero)
        console.log("User not exist!!!!!!!!!!!", results);
        return res.status(400).json({ message: "User Not Exist" });
      }

      const user = results[0]; //here we get the first element

      // Compare the provided password with the stored hashed password
      bcrypt.compare(password, user.password, (err, isMatch) => {
        if (err) {
          return res.status(500).send("Error comparing passwords");
        }
        if (!isMatch) {
          return res.status(400).json({ message: "Password incorrect" });
        }

        // here we Create JWT token and send it to the frontend whcih store it on local storage
        const token = jwt.sign(
          { id: user.id, role: user.role },
          "percyjackson",
          {
            expiresIn: "1h",
          }
        );
        res.json({ token });
      });
    }
  );
});

//--------------------------------------------------------------------------
// Protect API route based on role,this runs after user login, here we get the user info like role,names other fields to use (here mostly on frontend like rendering specific elements on user role)
app.get("/profile", (req, res) => {
  const token = req.headers["authorization"]; //from client side web token is send through http header

  if (!token) {
    //If no token is found in the request, the server responds with 403 Forbidden. This means the client is not authorized to access the route without a token.
    return res.status(403).send("No token provided");
  }

  jwt.verify(token, "percyjackson", (err, decoded) => {
    //It checks the token against a secret key "percyjackson". If the token is valid, it decodes the information inside (like user ID and role). If not, it returns an error.
    if (err) {
      return res.status(401).send("Invalid or expired token");
    }

    // Fetch user info from DB based on token
    db.query(
      "SELECT * FROM user WHERE id = ?",
      [decoded.id], //Once the token is verified and the user info is decoded, it retrieves the user data from the database by using the id from the decoded token (which was stored when the token was generated).
      (err, results) => {
        if (err) {
          return res.status(500).send("Database error");
        }
        res.json(results[0]);
      }
    );
  });
});
//------------------------------------------------------------------
//------------------------------------------------------------------

//------------------------------------------------------------------
//------------------------------------------------------------------
//this will give the crime page all the crimes in the database, now with crime location(shape Name)
app.get("/crimes", (req, res) => {
  db.query(
    `SELECT 
    c.crimeId,
    c.coordinateId,
    c.crimeType,
    c.details,
    c.crimeDate,
    ma.shapeName
FROM 
    crimes c
JOIN 
    coordinates co ON c.coordinateId = co.coordinateId
JOIN 
    mapArea ma ON co.ShapeId = ma.ShapeId AND co.pointId = ma.pointId;
`, //here we are getting all the crimes
    (err, results) => {
      if (err) {
        console.log(err);
        return res
          .status(500)
          .send(
            "Database error not fetching crimes from database!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
          );
      }

      res.json(results); //here we sending all the crimes rows
    }
  );
});
//------------------------------------------------------------------
//this will give the crime page on frontend the crime detail of the given crimeId
app.get("/crime/Detail/:crimeId", (req, res) => {
  const { crimeId } = req.params; // Get crimeId from URL parameter
  //{} this caused error, use ut for this case
  // Query to fetch crime details based on crimeId
  const query = `
    SELECT 
        crimes.crimeType,
        victims.name AS victimName,
        criminals.name AS criminalName,
        mapArea.shapeName AS sectorName
    FROM 
        crimes
    JOIN 
        victimOfCrime ON crimes.crimeId = victimOfCrime.crimeId
    JOIN 
        victims ON victimOfCrime.victimId = victims.victimId
    JOIN 
        committedCrime ON crimes.crimeId = committedCrime.crimeId
    JOIN 
        criminals ON committedCrime.criminalId = criminals.criminalId
    JOIN 
        coordinates ON crimes.coordinateId = coordinates.coordinateId
    JOIN 
        mapArea ON coordinates.ShapeId = mapArea.ShapeId AND coordinates.pointId = mapArea.pointId
    WHERE 
        crimes.crimeId = ?;
  `;

  db.query(query, [crimeId], (err, results) => {
    if (err) {
      console.error("Error fetching crime details:", err); // Log detailed error
      return res.status(500).send("Database error fetching crime details");
    }

    if (results.length === 0) {
      console.log("Crime with ID not found:", crimeId); // Log if crimeId doesn't exist
      return res.status(404).send("Crime not found");
    }

    // Return the results (crime details)
    res.json(results);
  });
});
///------------------------------------------------------------------
//--------------------------------------------------------
app.get("/crime/delete/:crimeId", (req, res) => {
  const { crimeId } = req.params; // Get crimeId from URL parameter

  // Start the transaction
  db.beginTransaction((err) => {
    if (err) {
      console.error("Error starting transaction:", err);
      return res.status(500).send("Database transaction error");
    }

    // 1. Delete from victimOfCrime
    const deleteVictimOfCrimeQuery =
      "DELETE FROM victimOfCrime WHERE crimeId = ?";
    db.query(deleteVictimOfCrimeQuery, [crimeId], (err) => {
      if (err) {
        console.error("Error deleting victimOfCrime:", err);
        return rollbackTransaction(res, "Error deleting victimOfCrime");
      }

      // 2. Delete from committedCrime
      const deleteCommittedCrimeQuery =
        "DELETE FROM committedCrime WHERE crimeId = ?";
      db.query(deleteCommittedCrimeQuery, [crimeId], (err) => {
        if (err) {
          console.error("Error deleting committedCrime:", err);
          return rollbackTransaction(res, "Error deleting committedCrime");
        }

        // 3. Delete the crime itself
        const deleteCrimeQuery = "DELETE FROM crimes WHERE crimeId = ?";
        db.query(deleteCrimeQuery, [crimeId], (err) => {
          if (err) {
            console.error("Error deleting crime:", err);
            return rollbackTransaction(res, "Error deleting crime");
          }

          // 4. Delete orphaned victims
          const deleteVictimsQuery = `
            DELETE FROM victims 
            WHERE victimId NOT IN (SELECT victimId FROM victimOfCrime)
          `;
          db.query(deleteVictimsQuery, (err) => {
            if (err) {
              console.error("Error deleting orphaned victims:", err);
              return rollbackTransaction(
                res,
                "Error deleting orphaned victims"
              );
            }

            // 5. Delete orphaned criminals
            const deleteCriminalsQuery = `
              DELETE FROM criminals 
              WHERE criminalId NOT IN (SELECT criminalId FROM committedCrime)
            `;
            db.query(deleteCriminalsQuery, (err) => {
              if (err) {
                console.error("Error deleting orphaned criminals:", err);
                return rollbackTransaction(
                  res,
                  "Error deleting orphaned criminals"
                );
              }

              // 6. Delete orphaned coordinates
              const deleteCoordinatesQuery = `
                DELETE FROM coordinates 
                WHERE coordinateId NOT IN (SELECT coordinateId FROM crimes)
              `;
              db.query(deleteCoordinatesQuery, (err) => {
                if (err) {
                  console.error("Error deleting coordinates:", err);
                  return rollbackTransaction(res, "Error deleting coordinates");
                }

                // Commit the transaction if all queries succeeded
                db.commit((err) => {
                  if (err) {
                    console.error("Error committing transaction:", err);
                    return rollbackTransaction(
                      res,
                      "Error committing transaction"
                    );
                  }

                  res.send({
                    message: "Crime and related data deleted successfully",
                  });
                });
              });
            });
          });
        });
      });
    });
  });

  // Helper function to rollback transaction on error
  function rollbackTransaction(res, errorMessage) {
    db.rollback(() => {
      res.status(500).send({ message: errorMessage }); // Send error message to frontend
    });
  }
});

//--------------------------------------------------------
///------------------------------------------------
//this will give the crime page all the crimes in the database
app.get("/criminals", (req, res) => {
  db.query(
    "SELECT * FROM criminals", //here we are getting all the crimimals
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .send("Database error not fetching criminals from database!!!!!!!");
      }
      res.json(results); //here we sending all the criminals rows
    }
  );
});
//------------------------------------------------------------------
//------------------------------------------------------------------

//this will give the crime page on frontend the crime detail of the given crimeId
app.get("/criminals/Detail/:criminalId", (req, res) => {
  const { criminalId } = req.params; // Get criminalId from URL parameter
  //{} this caused error, use ut for this case
  // Query to fetch crime details based on crimeId
  //output is like :'John Doe', '35', 'F11 Islamabad', 'Robbery', 'Robbery in F11 area, victim was threatened with a weapon.', '2024-12-01', 'F11', 'Alice Smith (Age: 30, Address: F11 Islamabad); Faylinn Hunter (Age: 29, Address: G11 Islamabad)'

  const query = `
  SELECT 
    criminals.name AS criminalName,
    criminals.age AS criminalAge,
    criminals.address AS criminalAddress,
    crimes.crimeType,
    crimes.details AS crimeDetails,
    crimes.crimeDate,
    mapArea.shapeName AS sectorName,
    GROUP_CONCAT(CONCAT(victims.name, ' (Age: ', victims.age, ', Address: ', victims.address, ')') SEPARATOR '; ') AS victimList
FROM 
    criminals
JOIN 
    committedCrime ON criminals.criminalId = committedCrime.criminalId
JOIN 
    crimes ON committedCrime.crimeId = crimes.crimeId
JOIN 
    coordinates ON crimes.coordinateId = coordinates.coordinateId
JOIN 
    mapArea ON coordinates.ShapeId = mapArea.ShapeId AND coordinates.pointId = mapArea.pointId
JOIN 
    victimOfCrime ON crimes.crimeId = victimOfCrime.crimeId
JOIN 
    victims ON victimOfCrime.victimId = victims.victimId
WHERE 
    criminals.criminalId = ?
GROUP BY 
    crimes.crimeId;

  `;

  db.query(query, [criminalId], (err, results) => {
    if (err) {
      console.error("Error fetching criminal details:", err); // Log detailed error
      return res.status(500).send("Database error fetching criminald details");
    }

    if (results.length === 0) {
      console.log("Criminal with ID not found:", crimeId); // Log if criminalId doesn't exist, hence we got zero rows
      return res.status(404).send("Cricriminalsme not found");
    }

    // Return the results (crime details)
    res.json(results);
  });
});
///-----------s---s----------------------------------
///------------------------------------------------
app.get("/updated-criminal-data/:criminalId", (req, res) => {
  const { criminalId } = req.params;
  console.log("//////////////////////////");
  console.log("//////////////////////////");
  console.log(criminalId);
  console.log("//////////////////////////");
  db.query(
    "SELECT * FROM criminals WHERE criminalId= ?",
    [criminalId],
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .send("Database error not fetching criminals from database!!!!!!!");
      }
      console.log(results);
      res.json(results); //here we sending all the criminals rows
    }
  );
});
///---------
// PUT route to update a criminal by ID
app.put("/criminals/update/:criminalId", (req, res) => {
  const { criminalId } = req.params; // Get the ID of the criminal to update
  const { name, age, address } = req.body; // Extract fields from the request body
  console.log("//////////////////////////");
  console.log(criminalId);
  console.log("//////////////////////////");
  // Validate required fields
  if (!name || !age || !address) {
    ss;
    return res
      .status(400)
      .json({ message: "All fields (name, age, address) are required." });
  }

  // SQL query to update the criminal record
  const query = `
        UPDATE criminals
        SET name = ?, age = ?, address = ?
        WHERE criminalId = ?;
    `;

  // Execute the query
  db.query(query, [name, age, address, criminalId], (err, result) => {
    if (err) {
      console.error("Error updating criminal:", err);
      return res
        .status(500)
        .json({ message: "Error updating criminal record." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Criminal not found." });
    }

    res.status(200).json({ message: "Criminal updated successfully." });
  });
});
///------------------------------------------------
///------------------------------------------------
//this will give the victims page all the victims in the database
app.get("/victims", (req, res) => {
  db.query(
    "SELECT * FROM victims", //here we are getting all the crimimals
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .send("Database error not fetching victims from database!!!!!!!");
      }
      res.json(results); //here we sending all the criminals rows
    }
  );
});
//------------------------------------------------------------------
//------------------------------------------------------------------
//------------------------------------------------------------------

//this will give the crime page on frontend the crime detail of the given crimeId
app.get("/victims/Detail/:victimId", (req, res) => {
  const { victimId } = req.params; // Get criminalId from URL parameter
  //{} this caused error, use ut for this case
  // Query to fetch crime details based on crimeId
  //output is like :'John Doe', '35', 'F11 Islamabad', 'Robbery', 'Robbery in F11 area, victim was threatened with a weapon.', '2024-12-01', 'F11', 'Alice Smith (Age: 30, Address: F11 Islamabad); Faylinn Hunter (Age: 29, Address: G11 Islamabad)'

  const query = `

  SELECT 
  victims.name AS victimName,
  victims.age AS victimAge,
  victims.address AS victimAddress,
  crimes.crimeType,
  crimes.details AS crimeDetails,
  crimes.crimeDate,
  mapArea.shapeName AS sectorName,
  criminals.name AS criminalName,
  criminals.age AS criminalAge,
  criminals.address AS criminalAddress
FROM 
  victims
JOIN 
  victimOfCrime ON victims.victimId = victimOfCrime.victimId
JOIN 
  crimes ON victimOfCrime.crimeId = crimes.crimeId
JOIN 
  committedCrime ON crimes.crimeId = committedCrime.crimeId
JOIN 
  criminals ON committedCrime.criminalId = criminals.criminalId
JOIN 
  coordinates ON crimes.coordinateId = coordinates.coordinateId
JOIN 
  mapArea ON coordinates.ShapeId = mapArea.ShapeId AND coordinates.pointId = mapArea.pointId
WHERE 
  victims.victimId = ? 
ORDER BY 
  crimes.crimeId, criminals.criminalId;


  `;

  db.query(query, [victimId], (err, results) => {
    if (err) {
      console.error("Error fetching victims details:", err); // Log detailed error
      return res.status(500).send("Database error fetching victims details");
    }

    if (results.length === 0) {
      console.log("Vicitms with ID not found:", crimeId); // Log if criminalId doesn't exist, hence we got zero rows
      return res.status(404).send("victims not found");
    }

    // Return the results (crime details)
    res.json(results);
  });
});
// ---------------------------------------------------------
// ---------------------------------------------------------
// ---------------------------------------------------------

///------------------------------------------------
app.get("/updated-victim-data/:victimId", (req, res) => {
  const { victimId } = req.params;
  console.log("//////////////////////////");
  console.log("//////////////////////////");
  console.log(victimId);
  console.log("//////////////////////////");
  db.query(
    "SELECT * FROM victims WHERE victimId= ?",
    [victimId],
    (err, results) => {
      if (err) {
        return res
          .status(500)
          .send("Database error not fetching criminals from database!!!!!!!");
      }
      console.log(results);
      res.json(results); //here we sending all the criminals rows
    }
  );
});
///-----------------------------------------------------------
// PUT route to update a criminal by ID
app.put("/victims/update/:victimId", (req, res) => {
  const { victimId } = req.params; // Get the ID of the criminal to update
  const { name, age, address } = req.body; // Extract fields from the request body
  console.log("//////////////////////////");
  console.log(victimId);
  console.log("//////////////////////////");
  // Validate required fields
  if (!name || !age || !address) {
    ss;
    return res
      .status(400)
      .json({ message: "All fields (name, age, address) are required." });
  }

  // SQL query to update the criminal record
  const query = `
        UPDATE victims
        SET name = ?, age = ?, address = ?
        WHERE victimId = ?;
    `;

  // Execute the query
  db.query(query, [name, age, address, victimId], (err, result) => {
    if (err) {
      console.error("Error updating victim:", err);
      return res.status(500).json({ message: "Error updating victim record." });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "victim not found." });
    }

    res.status(200).json({ message: "victim updated successfully." });
  });
});
// ---------------------------------------------------------
// ---------------------------------------------------------
// ---------------------------------------------------------
// -create--------
// ---------------------------------------------------------
// ---------------------------------------------------------
app.get("/get-victims", (req, res) => {
  const query = "SELECT * FROM victims ORDER BY name"; // Query to fetch all victims

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching victims:", err);
      return res.status(500).json({ error: "Error fetching victims" });
    }

    res.json(results); // Send the list of victims as the response
  });
});
//-------------------
app.get("/get-criminals", (req, res) => {
  const query = "SELECT * FROM criminals ORDER BY name"; // Query to fetch all criminals

  db.query(query, (err, results) => {
    if (err) {
      console.error("Error fetching criminals:", err);
      return res.status(500).json({ error: "Error fetching criminals" });
    }

    res.json(results); // Send the list of criminals as the response
  });
});
//-----------------------------------
// Route to create a new victim
app.post("/create-victim", (req, res) => {
  const { name, age, address } = req.body;

  const query = "INSERT INTO victims (name, age, address) VALUES (?, ?, ?)";
  db.query(query, [name, age, address], (err, result) => {
    if (err) {
      console.error("Error inserting victim:", err);
      return res.status(500).json({ error: "Error inserting victim" });
    }
    res.json({ victimId: result.insertId }); // Return the victimId of the newly created victim
  });
});

// Route to create a new criminal
app.post("/create-criminal", (req, res) => {
  const { name, age, address } = req.body;

  const query = "INSERT INTO criminals (name, age, address) VALUES (?, ?, ?)";
  db.query(query, [name, age, address], (err, result) => {
    if (err) {
      console.error("Error inserting criminal:", err);
      return res.status(500).json({ error: "Error inserting criminal" });
    }
    res.json({ criminalId: result.insertId }); // Return the criminalId of the newly created criminal
  });
});
/////------------------------------------------------
/////------------------------------------------------
/////------------------------------------------------

// Route to fetch map area data
app.get("/get-mapArea", (req, res) => {
  try {
    // Fetch the data from the database (updated query to include shapeName)
    const query = `
      SELECT shapeId, pointId, shapeName, longitude, latitude
      FROM mapArea
      ORDER BY shapeId, pointId;
    `;

    const shapesData = [];
    db.query(query, (err, result) => {
      if (err) {
        console.error("Error querying the database:", err);
        return res.status(500).json({ message: "Database Query Error" });
      }

      // Process the data to group by shapeId and pointId, and include shapeName
      console.log(result[0]); // Log the result from the query

      result.forEach((row) => {
        const shapeIndex = shapesData.findIndex(
          (shape) => shape.shapeId === row.shapeId
        );

        if (shapeIndex === -1) {
          // If shapeId is not found, create a new entry with shapeName
          shapesData.push({
            shapeId: row.shapeId,
            shapeName: row.shapeName, // Include shapeName here
            pointId: row.pointId,
            points: [{ longitude: row.longitude, latitude: row.latitude }],
          });
        } else {
          // If shapeId exists, push the point to the existing shape
          const shape = shapesData[shapeIndex];
          shape.points.push({
            longitude: row.longitude,
            latitude: row.latitude,
          });
        }
      });

      // Return the formatted data including shapeName
      // console.log(JSON.stringify(shapesData, null, 2)); // Log the formatted shapesData
      res.json(shapesData); // Send the response only after processing the data
    });
  } catch (error) {
    console.error("Error fetching map area data:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

/////------------------------------------------------
/////------------------------------------------------
/////------------------------------------------------
app.post("/create-crime", (req, res) => {
  const {
    crimeType,
    details,
    victimIds, // Array of victim IDs
    criminalIds, // Array of criminal IDs
    latitude,
    longitude,
    shapeId,
    pointId,
  } = req.body;

  // Step 1: Validate Input
  if (
    !crimeType ||
    !details ||
    latitude === undefined ||
    longitude === undefined
  ) {
    return res
      .status(400)
      .json({ error: "Invalid input. Please provide all required fields." });
  }

  // Step 2: Insert coordinates
  const coordQuery = `INSERT INTO coordinates (longitude, latitude, ShapeId, pointId) VALUES (?, ?, ?, ?)`;
  db.query(
    coordQuery,
    [longitude, latitude, shapeId, pointId],
    (err, coordResult) => {
      if (err) {
        console.error("Error inserting coordinates:", err);
        return res.status(500).json({ error: "Failed to insert coordinates." });
      }

      const coordinateId = coordResult.insertId;

      // Step 3: Insert crime record
      const crimeQuery = `INSERT INTO crimes (coordinateId, crimeType, details, crimeDate) VALUES (?, ?, ?, CURRENT_DATE)`;
      db.query(
        crimeQuery,
        [coordinateId, crimeType, details],
        (err, crimeResult) => {
          if (err) {
            console.error("Error inserting crime:", err);
            return res.status(500).json({ error: "Failed to insert crime." });
          }

          const crimeId = crimeResult.insertId;

          // Step 4: Link victims and crime
          if (Array.isArray(victimIds) && victimIds.length > 0) {
            const victimLinkQuery = `INSERT INTO victimOfCrime (crimeId, victimId) VALUES ?`;
            const victimData = victimIds.map((victimId) => [crimeId, victimId]);
            db.query(victimLinkQuery, [victimData], (err) => {
              if (err) console.error("Error linking victims to crime:", err);
            });
          }

          // Step 5: Link criminals and crime
          if (Array.isArray(criminalIds) && criminalIds.length > 0) {
            const criminalLinkQuery = `INSERT INTO committedCrime (crimeId, criminalId) VALUES ?`;
            const criminalData = criminalIds.map((criminalId) => [
              crimeId,
              criminalId,
            ]);
            db.query(criminalLinkQuery, [criminalData], (err) => {
              if (err) {
                console.error("Error linking criminals to crime:", err);
                return res
                  .status(500)
                  .json({ error: "Failed to link criminals to crime." });
              }
              return res.json({
                message: "Crime created successfully",
                crimeId,
              });
            });
          } else {
            res.json({ message: "Crime created successfully", crimeId });
          }
        }
      );
    }
  );
});

//------------------------------------------------------------------
//------------------------------------------------------------------
//-----------UPDATE------------------------------------------
// GET route to fetch crime data by crimeId
// GET route to fetch crime data by crimeId
app.get("/get-crime/:crimeId", (req, res) => {
  const { crimeId } = req.params;

  const query = `
    SELECT 
      c.crimeId, 
      c.coordinateId, 
      c.crimeType, 
      c.details, 
      co.latitude, 
      co.longitude, 
      co.ShapeId, 
      co.pointId, 
      GROUP_CONCAT(DISTINCT v.victimId) AS victimIds,
      GROUP_CONCAT(DISTINCT cr.criminalId) AS criminalIds
    FROM crimes c
    JOIN coordinates co ON c.coordinateId = co.coordinateId
    LEFT JOIN victimOfCrime vc ON c.crimeId = vc.crimeId
    LEFT JOIN victims v ON vc.victimId = v.victimId
    LEFT JOIN committedCrime cc ON c.crimeId = cc.crimeId
    LEFT JOIN criminals cr ON cc.criminalId = cr.criminalId
    WHERE c.crimeId = ?
    GROUP BY c.crimeId, co.latitude, co.longitude, co.ShapeId, co.pointId;
  `;

  db.query(query, [crimeId], (error, rows) => {
    if (error) {
      console.error("Error fetching crime data:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    if (rows.length > 0) {
      res.json(rows[0]);
    } else {
      res.status(404).json({ error: "Crime not found" });
    }
  });
});

////////////////////////

// PUT route to update crime data
app.put("/update-crime", (req, res) => {
  const {
    crimeId,
    crimeType,
    details,
    latitude,
    longitude,
    shapeId,
    pointId,
    victimIds,
    criminalIds,
    coordinateId,
  } = req.body;

  if (!crimeId) {
    console.error("Missing crimeId");
    return res.status(400).json({ message: "Crime ID is required." });
  }

  console.log("Received crime details:", req.body);

  // Start a transaction
  db.beginTransaction((error) => {
    if (error) {
      console.error("Error starting transaction:", error);
      return res.status(500).json({ error: "Internal Server Error" });
    }

    // 1. Update the crime record
    const updateCrimeQuery = `
      UPDATE crimes
      SET crimeType = ?, details = ?
      WHERE crimeId = ?;
    `;
    db.query(updateCrimeQuery, [crimeType, details, crimeId], (error) => {
      if (error) {
        console.error("Error updating crime:", error);
        return db.rollback(() => {
          return res.status(500).json({ error: "Internal Server Error" });
        });
      }

      // 2. Update coordinates (latitude and longitude)
      const updateCoordinatesQuery = `
        UPDATE coordinates
        SET latitude = ?, longitude = ?,shapeId = ?, pointId = ?
        WHERE coordinateId = ?;
      `;
      db.query(
        updateCoordinatesQuery,
        [latitude, longitude, shapeId, pointId, coordinateId],
        (error) => {
          if (error) {
            console.error("Error updating coordinates:", error);
            return db.rollback(() => {
              return res.status(500).json({ error: "Internal Server Error" });
            });
          }

          // 3. Remove old victim and criminal associations
          const removeVictimsQuery = `
            DELETE FROM victimOfCrime WHERE crimeId = ?;
          `;
          db.query(removeVictimsQuery, [crimeId], (error) => {
            if (error) {
              console.error("Error removing victims:", error);
              return db.rollback(() => {
                return res.status(500).json({ error: "Internal Server Error" });
              });
            }

            const removeCriminalsQuery = `
              DELETE FROM committedCrime WHERE crimeId = ?;
            `;
            db.query(removeCriminalsQuery, [crimeId], (error) => {
              if (error) {
                console.error("Error removing criminals:", error);
                return db.rollback(() => {
                  return res
                    .status(500)
                    .json({ error: "Internal Server Error" });
                });
              }

              // Add new associations
              let victimQueryCount = 0;
              let criminalQueryCount = 0;
              let totalQueries = victimIds.length + criminalIds.length;

              const addVictimsQuery = `
                INSERT INTO victimOfCrime (crimeId, victimId)
                VALUES (?, ?);
              `;
              victimIds.forEach((victimId) => {
                db.query(addVictimsQuery, [crimeId, victimId], (error) => {
                  if (error) {
                    console.error("Error adding victims:", error);
                    return db.rollback(() => {
                      return res
                        .status(500)
                        .json({ error: "Internal Server Error" });
                    });
                  }
                  victimQueryCount++;
                  if (victimQueryCount + criminalQueryCount === totalQueries) {
                    commitTransaction();
                  }
                });
              });

              const addCriminalsQuery = `
                INSERT INTO committedCrime (crimeId, criminalId)
                VALUES (?, ?);
              `;
              criminalIds.forEach((criminalId) => {
                db.query(addCriminalsQuery, [crimeId, criminalId], (error) => {
                  if (error) {
                    console.error("Error adding criminals:", error);
                    return db.rollback(() => {
                      return res
                        .status(500)
                        .json({ error: "Internal Server Error" });
                    });
                  }
                  criminalQueryCount++;
                  if (victimQueryCount + criminalQueryCount === totalQueries) {
                    commitTransaction();
                  }
                });
              });

              // Commit transaction once everything is successful
              function commitTransaction() {
                db.commit((error) => {
                  if (error) {
                    console.error("Error committing transaction:", error);
                    return db.rollback(() => {
                      return res
                        .status(500)
                        .json({ error: "Internal Server Error" });
                    });
                  }

                  res.json({ message: "Crime record updated successfully!" });
                });
              }
            });
          });
        }
      );
    });
  });
});

////////////-
////////////-
////////////-
// DELETE victim by victimId
// Endpoint to remove a victim from a crime
app.get("/delete-victim/:crimeId/:victimId", (req, res) => {
  const { crimeId, victimId } = req.params;

  // Start transaction to ensure atomic operations
  db.beginTransaction((err) => {
    if (err) {
      console.error("Error starting transaction:", err);
      return res.status(500).send("Error starting transaction");
    }

    // 1. Delete the victim from the victimOfCrime table
    const deleteVictimOfCrimeQuery =
      "DELETE FROM victimOfCrime WHERE crimeId = ? AND victimId = ?";
    db.query(deleteVictimOfCrimeQuery, [crimeId, victimId], (err) => {
      if (err) {
        console.error("Error deleting victimOfCrime:", err);
        return db.rollback(() => {
          res.status(500).send("Error deleting victimOfCrime");
        });
      }

      // 2. Optionally: Delete orphaned victims (victims not associated with any crime)
      const deleteVictimsQuery = `
        DELETE FROM victims
        WHERE victimId NOT IN (SELECT victimId FROM victimOfCrime)
      `;
      db.query(deleteVictimsQuery, (err) => {
        if (err) {
          console.error("Error deleting orphaned victims:", err);
          return db.rollback(() => {
            res.status(500).send("Error deleting orphaned victims");
          });
        }

        // 3. Commit the transaction
        db.commit((err) => {
          if (err) {
            console.error("Error committing transaction:", err);
            return db.rollback(() => {
              res.status(500).send("Error committing transaction");
            });
          }
          res.send("Victim removed successfully");
        });
      });
    });
  });
});

// Endpoint to remove a criminal from a crime
app.get("/delete-criminal/:crimeId/:criminalId", (req, res) => {
  const { crimeId, criminalId } = req.params;

  // Start transaction to ensure atomic operations
  db.beginTransaction((err) => {
    if (err) {
      console.error("Error starting transaction:", err);
      return res.status(500).send("Error starting transaction");
    }

    // 1. Delete the criminal from the committedCrime table
    const deleteCommittedCrimeQuery =
      "DELETE FROM committedCrime WHERE crimeId = ? AND criminalId = ?";
    db.query(deleteCommittedCrimeQuery, [crimeId, criminalId], (err) => {
      if (err) {
        console.error("Error deleting committedCrime:", err);
        return db.rollback(() => {
          res.status(500).send("Error deleting committedCrime");
        });
      }

      // 2. Optionally: Delete orphaned criminals (criminals not associated with any crime)
      const deleteCriminalsQuery = `
        DELETE FROM criminals 
        WHERE criminalId NOT IN (SELECT criminalId FROM committedCrime)
      `;
      db.query(deleteCriminalsQuery, (err) => {
        if (err) {
          console.error("Error deleting orphaned criminals:", err);
          return db.rollback(() => {
            res.status(500).send("Error deleting orphaned criminals");
          });
        }

        // 3. Commit the transaction
        db.commit((err) => {
          if (err) {
            console.error("Error committing transaction:", err);
            return db.rollback(() => {
              res.status(500).send("Error committing transaction");
            });
          }
          res.send("Criminal removed successfully");
        });
      });
    });
  });
});

//------------------------------------------------------------------
//------------------------------------------------------------------
//------------------------------------------------------------------
// Start the server
const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});

## Project Item catalog

Flask project for Udaicty fullstack course implemented acording to requirements.

## Requirements

This script is written to run inside vagrant with the FSDN-virtual machine setup found [here](https://github.com/udacity/fullstack-nanodegree-vm)

## Instructions

Login to the vagrant machine and go to where you have the files located.

I have included a catalog.db file with this project for testing.

To test with a blank database either delete or make a backup of catalog.db.

Run the db_setup.py to setup the database model.

`python db_setup.py`

To start the web server on port 5000 run the project.py file.

`python project.py`

Go to http://localhost:5000 in your web browser.

JSON endpoints available:

Full catalog:
`http://localhost:5000/catalog/json`

Category listing
`http://localhost:5000/catalog/<category_name>/json`

Singel item listing
`http://localhost:5000/catalog/<category_name>/<item_name>/json`

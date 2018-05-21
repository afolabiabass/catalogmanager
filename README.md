# Catalog Manager
A Python built web application using the Flask framework. Create and manage catalog with each catalog having various items associated to the catalog.

## Requirements

* Vagrant
* VirtualBox
* Python v2.7
* PostgreSQL
* psycopg2

## Instructions
To run this analysis follow the instructions given below

* Once you have Vagrant and VirtualBox installed on your computer
* Download the contents of this file
* From the command line, navigate to the folder containing the contant of this file
* Power up the virtual machine by typing: vagrant up note: this may take a couple minutes to complete
* Once the virtual machine is done booting, log into it by typing: vagrant ssh
* Now that you are logged into the virtual machine go to the directory shared directory /vagrant/catalog
* Run the psql -c "create database catalogdb" to set up a database for the web application
* Run python models.py to create all the tables and necessary relationship
* Finally run python app.py
* You should now be able to access the web application on localhost:5000 9)

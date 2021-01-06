Keycloak Fun Extention
=======================

This project is an attempt to set a project which can be deployed and customized in keycloak.

Demo
----

This is the main example, which shows Login customization, Single-Sign On, Single-Sign Out. 

Themes
------

Example themes to change the look and feel of login forms, account management console and admin console. 
For more information look at `themes/README.md`.


Useful commands

    `docker run -it -p 8080:8080 -p 9990:9990 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin --rm <image_name>`

# hospitalbackend
# install all the requirements.txt file
#use pip install -r requirements.txt
#I used python version 3.11.6 to built the system.
# create a .env file inside the project, and add random numbers as fields for the secret key
#project secret key
#SECRET_KEY = any random numbers 
#SECRET_ENCRYPTION_KEY = #secretkey for cryptography encryption
#OPENAI_API_KEY  = #secret keys for open Ai
#If you are using a different version of python, after installing the requirements, modify the pipfile, and after that run pipenv update
#If You don't have pipenv on your device, use pip to install pipenv (pip install pipenv)
#if you don't have python on your device, you can install python version 3.11.6 to avoid #conflicts.
#summary
#pip install pipenv if you don't have pipenv of your device
#inside the project, create a .env file, this file will contain all the secret keys of the #project, Open the terminal and navigate into the project if you created a folder and the #project is that folder, if not just open the terminal and run pip install -r requirements.#txt
#After installations, use python manage.py runserver 
# This will run the server and you can check the urls.py file in the authentication app, to #tests the APIS,
#for easy access, run python manage.py createsuperuser on the terminal to create a #superuser, so that you can access the admin dashboard, Since some of the pages requires #authentication, 


# FINAL-IHM

A FastAPI web app with user registration, login, admin dashboard, and product showcase (AC/DC Back in Black vinyl).

## Features
- User registration and login (JWT-based)
- Admin dashboard: view users, change roles/passwords
- User dashboard: product ad (AC/DC Back in Black vinyl)
- Change password, logout (token revocation)
- Modern UI, role-based access

## Quickstart
## Deploying to Vercel (with Magnum)

1. Make sure you have [Vercel CLI](https://vercel.com/download) installed and are logged in.
2. This project is ready for Vercel Python/Magnum:
	- `vercel.json` is included for routing static files and API requests.
	- All static assets (HTML, CSS, images) must be in the `static/` folder.
3. Deploy:
	```sh
	vercel --prod
	```

**Note:** If you add or update static files, re-deploy to see changes.
1. **Install requirements** (in your venv):
	```powershell
	pip install -r requirements.txt
	```
2. **Run the app:**
	```powershell
	uvicorn main:app --reload
	```
3. **Open in browser:**
	[http://localhost:8000](http://localhost:8000)

- Default admin: `admin` / `admin123`
- To show the album cover, place `back_in_black.jpg` in the `static/` folder.

## Project structure
- `main.py` — FastAPI app, routes
- `models.py`, `database.py` — ORM models, DB setup
- `static/` — HTML, CSS, images
- `requirements.txt` — dependencies

---
*Built with FastAPI, SQLAlchemy, and modern HTML/CSS.*
# FINAL-IHM
Proejct done by 
Bourras Abdel Moumen
Boucetta Ayoub 
Guessoum Oussama 


Major techs 

FastAPI
SQLAlchemy
python-jwt
bcrypt for hash
uvicorn 
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
import sqlite3
import json
import jwt
from passlib.context import CryptContext

app = FastAPI(title="API Nutricional", version="1.0.0")

# Configuración de seguridad
SECRET_KEY = "your-secret-key-here"  # Cambiar en producción
ALGORITHM = "HS256"
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Modelos Pydantic para validación
class UserCreate(BaseModel):
    email: str
    password: str
    role: str  # 'patient' o 'nutritionist'
    first_name: str
    last_name: str
    birth_date: str
    phone: str
    height: Optional[float] = None
    weight: Optional[float] = None
    has_medical_condition: int = 0
    chronic_disease: Optional[str] = None
    allergies: Optional[str] = None
    dietary_preferences: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    user_id: int
    email: str
    role: str
    first_name: str
    last_name: str
    birth_date: str
    phone: str
    height: Optional[float]
    weight: Optional[float]
    has_medical_condition: int
    chronic_disease: Optional[str]
    allergies: Optional[str]
    dietary_preferences: Optional[str]
    created_at: str

class MedicalRecordCreate(BaseModel):
    patients_users_user_id: int
    nutritionists_users_user_id: int
    appointments_appointments_id: int
    healthcare_facility: str
    service_date: str
    residence_location: str
    family_nucleus: str
    occupation: str
    education_level: str
    marital_status: str
    religion: str
    id_number: str
    previous_diagnosis: Optional[str] = None
    illness_duration: Optional[str] = None
    recent_diagnosis: Optional[str] = None
    family_history: Optional[str] = None

class MealCreate(BaseModel):
    name: str
    description: str
    calories: int
    prep_time_minutes: int

class NutritionPlanCreate(BaseModel):
    nutritionists_users_id: int
    patients_users_user_id: int
    medical_records_rec: int
    energy_requirement: int
    status: str = 'pending'

class PlanDetailCreate(BaseModel):
    nutrition_plan_id: int
    meal_type: str
    description: str
    meals_meal_id: int

# Nuevos modelos para respuestas completas
class MealResponse(BaseModel):
    meal_id: int
    name: str
    description: str
    calories: int
    prep_time_minutes: int
    creation_date: str

class PlanDetailResponse(BaseModel):
    detail_id: int
    nutrition_plan_id: int
    meal_type: str
    description: str
    creation_date: str
    meal: MealResponse  # Incluir información de la comida

class NutritionPlanResponse(BaseModel):
    plan_id: int
    nutritionists_users_id: int
    patients_users_user_id: int
    medical_records_rec: int
    energy_requirement: int
    creation_date: str
    status: str
    details: List[PlanDetailResponse] = []  # Incluir detalles del plan

# Función para conectar a la base de datos
def get_db_connection():
    conn = sqlite3.connect('nutrition.db')
    conn.row_factory = sqlite3.Row
    return conn

# Función para verificar contraseña
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Función para hashear contraseña
def get_password_hash(password):
    return pwd_context.hash(password)

# Función para crear token JWT
def create_access_token(data: dict):
    to_encode = data.copy()
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Función para obtener usuario actual del token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Token inválido")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user is None:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    return dict(user)

# Función para inicializar la base de datos
def init_db():
    conn = get_db_connection()
    
    # Crear tablas si no existen (mismo código que antes)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            birth_date TEXT,
            phone TEXT,
            height REAL,
            weight REAL,
            has_medical_condition INTEGER DEFAULT 0,
            chronic_disease TEXT,
            allergies TEXT,
            dietary_preferences TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS medical_records (
            record_id INTEGER PRIMARY KEY AUTOINCREMENT,
            patients_users_user_id INTEGER,
            nutritionists_users_user_id INTEGER,
            appointments_appointments_id INTEGER,
            healthcare_facility TEXT,
            service_date TEXT,
            residence_location TEXT,
            family_nucleus TEXT,
            occupation TEXT,
            education_level TEXT,
            marital_status TEXT,
            religion TEXT,
            id_number TEXT,
            previous_diagnosis TEXT,
            illness_duration TEXT,
            recent_diagnosis TEXT,
            family_history TEXT,
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patients_users_user_id) REFERENCES users (user_id),
            FOREIGN KEY (nutritionists_users_user_id) REFERENCES users (user_id)
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS meals (
            meal_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            calories INTEGER,
            prep_time_minutes INTEGER,
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS nutrition_plans (
            plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            nutritionists_users_id INTEGER,
            patients_users_user_id INTEGER,
            medical_records_rec INTEGER,
            energy_requirement INTEGER,
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (nutritionists_users_id) REFERENCES users (user_id),
            FOREIGN KEY (patients_users_user_id) REFERENCES users (user_id),
            FOREIGN KEY (medical_records_rec) REFERENCES medical_records (record_id)
        )
    ''')
    
    conn.execute('''
        CREATE TABLE IF NOT EXISTS plan_details (
            detail_id INTEGER PRIMARY KEY AUTOINCREMENT,
            nutrition_plan_id INTEGER,
            meal_type TEXT,
            description TEXT,
            creation_date TEXT DEFAULT CURRENT_TIMESTAMP,
            meals_meal_id INTEGER,
            FOREIGN KEY (nutrition_plan_id) REFERENCES nutrition_plans (plan_id),
            FOREIGN KEY (meals_meal_id) REFERENCES meals (meal_id)
        )
    ''')
    
    conn.commit()
    conn.close()

# Inicializar DB al arrancar
@app.on_event("startup")
async def startup_event():
    init_db()

# ================================
# ENDPOINTS DE AUTENTICACIÓN
# ================================

@app.post("/register")
async def register(user: UserCreate):
    """Registrar un nuevo usuario"""
    conn = get_db_connection()
    now = datetime.now().isoformat()
    
    # Hashear contraseña
    hashed_password = get_password_hash(user.password)
    
    try:
        cursor = conn.execute('''
            INSERT INTO users (email, password, role, first_name, last_name, birth_date, 
                             phone, height, weight, has_medical_condition, chronic_disease, 
                             allergies, dietary_preferences, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user.email, hashed_password, user.role, user.first_name, user.last_name,
              user.birth_date, user.phone, user.height, user.weight, 
              user.has_medical_condition, user.chronic_disease, user.allergies,
              user.dietary_preferences, now, now))
        
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Crear token
        token = create_access_token({"user_id": user_id, "role": user.role})
        
        return {"message": "Usuario registrado exitosamente", "user_id": user_id, "token": token}
    
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="El email ya existe")

@app.post("/login")
async def login(user_login: UserLogin):
    """Iniciar sesión"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (user_login.email,)).fetchone()
    conn.close()
    
    if not user or not verify_password(user_login.password, user['password']):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    
    token = create_access_token({"user_id": user['user_id'], "role": user['role']})
    
    return {"token": token, "user_id": user['user_id'], "role": user['role']}

# ================================
# ENDPOINTS PARA USUARIOS
# ================================

@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """Obtener información del usuario actual"""
    return current_user

@app.get("/users", response_model=List[UserResponse])
async def get_users(current_user: dict = Depends(get_current_user)):
    """Obtener todos los usuarios (solo nutricionistas)"""
    if current_user['role'] != 'nutritionist':
        raise HTTPException(status_code=403, detail="Acceso denegado")
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    return [dict(user) for user in users]

# ================================
# ENDPOINTS PARA PLANES NUTRICIONALES (MEJORADOS)
# ================================

@app.get("/nutrition-plans/my-plans")
async def get_my_nutrition_plans(current_user: dict = Depends(get_current_user)):
    """Obtener planes nutricionales del usuario actual"""
    conn = get_db_connection()
    
    if current_user['role'] == 'patient':
        # Si es paciente, obtener sus planes
        plans = conn.execute(
            'SELECT * FROM nutrition_plans WHERE patients_users_user_id = ?', 
            (current_user['user_id'],)
        ).fetchall()
    else:
        # Si es nutricionista, obtener planes que ha creado
        plans = conn.execute(
            'SELECT * FROM nutrition_plans WHERE nutritionists_users_id = ?', 
            (current_user['user_id'],)
        ).fetchall()
    
    # Para cada plan, obtener sus detalles con las comidas
    result = []
    for plan in plans:
        plan_dict = dict(plan)
        
        # Obtener detalles del plan con información de las comidas
        details_query = '''
            SELECT pd.*, m.name as meal_name, m.description as meal_description, 
                   m.calories, m.prep_time_minutes, m.creation_date as meal_creation_date
            FROM plan_details pd
            JOIN meals m ON pd.meals_meal_id = m.meal_id
            WHERE pd.nutrition_plan_id = ?
        '''
        details = conn.execute(details_query, (plan['plan_id'],)).fetchall()
        
        plan_details = []
        for detail in details:
            detail_dict = {
                'detail_id': detail['detail_id'],
                'nutrition_plan_id': detail['nutrition_plan_id'],
                'meal_type': detail['meal_type'],
                'description': detail['description'],
                'creation_date': detail['creation_date'],
                'meal': {
                    'meal_id': detail['meals_meal_id'],
                    'name': detail['meal_name'],
                    'description': detail['meal_description'],
                    'calories': detail['calories'],
                    'prep_time_minutes': detail['prep_time_minutes'],
                    'creation_date': detail['meal_creation_date']
                }
            }
            plan_details.append(detail_dict)
        
        plan_dict['details'] = plan_details
        result.append(plan_dict)
    
    conn.close()
    return result

@app.get("/nutrition-plans/{plan_id}")
async def get_nutrition_plan_by_id(plan_id: int, current_user: dict = Depends(get_current_user)):
    """Obtener un plan nutricional específico con sus detalles"""
    conn = get_db_connection()
    
    # Verificar que el usuario tenga acceso al plan
    plan = conn.execute('SELECT * FROM nutrition_plans WHERE plan_id = ?', (plan_id,)).fetchone()
    
    if not plan:
        conn.close()
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    
    # Verificar permisos
    if (current_user['role'] == 'patient' and plan['patients_users_user_id'] != current_user['user_id']) or \
       (current_user['role'] == 'nutritionist' and plan['nutritionists_users_id'] != current_user['user_id']):
        conn.close()
        raise HTTPException(status_code=403, detail="Acceso denegado")
    
    plan_dict = dict(plan)
    
    # Obtener detalles del plan con información de las comidas
    details_query = '''
        SELECT pd.*, m.name as meal_name, m.description as meal_description, 
               m.calories, m.prep_time_minutes, m.creation_date as meal_creation_date
        FROM plan_details pd
        JOIN meals m ON pd.meals_meal_id = m.meal_id
        WHERE pd.nutrition_plan_id = ?
        ORDER BY pd.meal_type, pd.creation_date
    '''
    details = conn.execute(details_query, (plan_id,)).fetchall()
    
    plan_details = []
    for detail in details:
        detail_dict = {
            'detail_id': detail['detail_id'],
            'nutrition_plan_id': detail['nutrition_plan_id'],
            'meal_type': detail['meal_type'],
            'description': detail['description'],
            'creation_date': detail['creation_date'],
            'meal': {
                'meal_id': detail['meals_meal_id'],
                'name': detail['meal_name'],
                'description': detail['meal_description'],
                'calories': detail['calories'],
                'prep_time_minutes': detail['prep_time_minutes'],
                'creation_date': detail['meal_creation_date']
            }
        }
        plan_details.append(detail_dict)
    
    plan_dict['details'] = plan_details
    conn.close()
    
    return plan_dict

@app.post("/nutrition-plans")
async def create_nutrition_plan(plan: NutritionPlanCreate, current_user: dict = Depends(get_current_user)):
    """Crear un nuevo plan nutricional (solo nutricionistas)"""
    if current_user['role'] != 'nutritionist':
        raise HTTPException(status_code=403, detail="Solo los nutricionistas pueden crear planes")
    
    conn = get_db_connection()
    now = datetime.now().isoformat()
    
    cursor = conn.execute('''
        INSERT INTO nutrition_plans (nutritionists_users_id, patients_users_user_id,
                                   medical_records_rec, energy_requirement, 
                                   creation_date, status)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (current_user['user_id'], plan.patients_users_user_id,
          plan.medical_records_rec, plan.energy_requirement, now, plan.status))
    
    plan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"message": "Plan nutricional creado exitosamente", "plan_id": plan_id}

# ================================
# ENDPOINTS PARA DETALLES DE PLAN (MEJORADOS)
# ================================

@app.get("/plan-details/plan/{plan_id}")
async def get_plan_details_by_plan(plan_id: int, current_user: dict = Depends(get_current_user)):
    """Obtener detalles de un plan específico con información de las comidas"""
    conn = get_db_connection()
    
    # Verificar que el usuario tenga acceso al plan
    plan = conn.execute('SELECT * FROM nutrition_plans WHERE plan_id = ?', (plan_id,)).fetchone()
    
    if not plan:
        conn.close()
        raise HTTPException(status_code=404, detail="Plan no encontrado")
    
    # Verificar permisos
    if (current_user['role'] == 'patient' and plan['patients_users_user_id'] != current_user['user_id']) or \
       (current_user['role'] == 'nutritionist' and plan['nutritionists_users_id'] != current_user['user_id']):
        conn.close()
        raise HTTPException(status_code=403, detail="Acceso denegado")
    
    # Obtener detalles con información de las comidas
    details_query = '''
        SELECT pd.*, m.name as meal_name, m.description as meal_description, 
               m.calories, m.prep_time_minutes, m.creation_date as meal_creation_date
        FROM plan_details pd
        JOIN meals m ON pd.meals_meal_id = m.meal_id
        WHERE pd.nutrition_plan_id = ?
        ORDER BY pd.meal_type, pd.creation_date
    '''
    details = conn.execute(details_query, (plan_id,)).fetchall()
    conn.close()
    
    result = []
    for detail in details:
        detail_dict = {
            'detail_id': detail['detail_id'],
            'nutrition_plan_id': detail['nutrition_plan_id'],
            'meal_type': detail['meal_type'],
            'description': detail['description'],
            'creation_date': detail['creation_date'],
            'meal': {
                'meal_id': detail['meals_meal_id'],
                'name': detail['meal_name'],
                'description': detail['meal_description'],
                'calories': detail['calories'],
                'prep_time_minutes': detail['prep_time_minutes'],
                'creation_date': detail['meal_creation_date']
            }
        }
        result.append(detail_dict)
    
    return result

@app.post("/plan-details")
async def create_plan_detail(detail: PlanDetailCreate, current_user: dict = Depends(get_current_user)):
    """Crear un nuevo detalle de plan (solo nutricionistas)"""
    if current_user['role'] != 'nutritionist':
        raise HTTPException(status_code=403, detail="Solo los nutricionistas pueden crear detalles de plan")
    
    conn = get_db_connection()
    
    # Verificar que el plan pertenezca al nutricionista actual
    plan = conn.execute(
        'SELECT * FROM nutrition_plans WHERE plan_id = ? AND nutritionists_users_id = ?', 
        (detail.nutrition_plan_id, current_user['user_id'])
    ).fetchone()
    
    if not plan:
        conn.close()
        raise HTTPException(status_code=403, detail="No tienes permiso para modificar este plan")
    
    now = datetime.now().isoformat()
    
    cursor = conn.execute('''
        INSERT INTO plan_details (nutrition_plan_id, meal_type, description,
                                creation_date, meals_meal_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (detail.nutrition_plan_id, detail.meal_type, detail.description,
          now, detail.meals_meal_id))
    
    detail_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"message": "Detalle de plan creado exitosamente", "detail_id": detail_id}

# ================================
# ENDPOINTS PARA COMIDAS
# ================================

@app.get("/meals")
async def get_meals(current_user: dict = Depends(get_current_user)):
    """Obtener todas las comidas"""
    conn = get_db_connection()
    meals = conn.execute('SELECT * FROM meals ORDER BY name').fetchall()
    conn.close()
    
    return [dict(meal) for meal in meals]

@app.post("/meals")
async def create_meal(meal: MealCreate, current_user: dict = Depends(get_current_user)):
    """Crear una nueva comida (solo nutricionistas)"""
    if current_user['role'] != 'nutritionist':
        raise HTTPException(status_code=403, detail="Solo los nutricionistas pueden crear comidas")
    
    conn = get_db_connection()
    now = datetime.now().isoformat()
    
    cursor = conn.execute('''
        INSERT INTO meals (name, description, calories, prep_time_minutes, creation_date)
        VALUES (?, ?, ?, ?, ?)
    ''', (meal.name, meal.description, meal.calories, meal.prep_time_minutes, now))
    
    meal_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"message": "Comida creada exitosamente", "meal_id": meal_id}

# ================================
# ENDPOINT DE PRUEBA
# ================================

@app.get("/")
async def root():
    return {"message": "API Nutricional funcionando correctamente"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
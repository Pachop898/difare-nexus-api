"""
DIFARE NEXUS API con Autenticación
Versión serverless para Vercel + Login seguro
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import anthropic
import pandas as pd
import glob
import os
import threading
import time
import hashlib
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"]},
    r"/*": {"origins": "*"}
})

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# ── USUARIOS Y CONTRASEÑAS (ENCRIPTADAS) ──
# Puedes cambiar estos valores cuando quieras
USUARIOS = {
    "francisco": hashlib.sha256("pass123".encode()).hexdigest(),
    "mercaderista1": hashlib.sha256("difare2026".encode()).hexdigest(),
    "gerente_ventas": hashlib.sha256("ventas123".encode()).hexdigest(),
}

# Tokens de sesión (simples, no production-grade)
SESIONES_ACTIVAS = {}

# ── CACHE GLOBAL ──
_df_cache = None
_cache_timestamp = None
_cache_lock = threading.Lock()
CACHE_EXPIRY = 3600

def cargar_datos_async():
    """Carga datos en background"""
    global _df_cache, _cache_timestamp
    with _cache_lock:
        carpeta = "excels"
        if not os.path.exists(carpeta):
            carpeta = "./excels"
        if not os.path.exists(carpeta):
            carpeta = "../excels"
        
        archivos = [f for f in glob.glob(f"{carpeta}/*.xlsx") if "EJEMPLO" not in f.upper()]
        if not archivos:
            print(f"⚠️  Sin archivos en {carpeta}")
            _df_cache = pd.DataFrame()
            _cache_timestamp = time.time()
            return
        
        dfs = []
        print(f"📦 Cargando datos desde {carpeta}...")
        for a in archivos:
            try:
                df = pd.read_excel(a)
                if "FECHA" in df.columns and "DIA" not in df.columns:
                    df["DIA"] = df["FECHA"].astype(str)
                dfs.append(df)
                print(f"  ✓ {os.path.basename(a)}: {len(df):,} filas")
            except Exception as e:
                print(f"  ✗ {os.path.basename(a)}: {e}")
        
        _df_cache = pd.concat(dfs, ignore_index=True) if dfs else pd.DataFrame()
        _cache_timestamp = time.time()
        print(f"✅ Total: {len(_df_cache):,} filas cargadas\n")

def cargar_datos():
    """Retorna datos cacheados con refresh automático"""
    global _df_cache, _cache_timestamp
    
    if _df_cache is None:
        cargar_datos_async()
        return _df_cache
    
    if time.time() - _cache_timestamp > CACHE_EXPIRY:
        threading.Thread(target=cargar_datos_async, daemon=True).start()
    
    return _df_cache

def verificar_token(token):
    """Verifica si un token es válido"""
    return token in SESIONES_ACTIVAS and SESIONES_ACTIVAS[token] > time.time()

def parsear_mes_fecha(dia_str):
    """Parsea fechas en múltiples formatos"""
    s = str(dia_str).strip()
    if "/" in s:
        try:
            return pd.to_datetime(s, format="%Y/%m/%d").to_period("M").strftime("%Y-%m")
        except:
            return "desconocido"
    elif len(s) == 6 and s.isdigit():
        return s[:4] + "-" + s[4:6]
    elif len(s) == 8 and s.isdigit():
        try:
            return pd.to_datetime(s, format="%Y%m%d").to_period("M").strftime("%Y-%m")
        except:
            return "desconocido"
    else:
        return s[:7] if len(s) >= 7 else "desconocido"

def obtener_stock_pos(pos, df):
    """Obtiene stock en tiempo real del SAP"""
    sap_files = [f for f in glob.glob("excels/*.xlsx") if "SAP" in f.upper()]
    if not sap_files:
        sap_files = [f for f in glob.glob("./excels/*.xlsx") if "SAP" in f.upper()]
    if not sap_files:
        return {"mensaje": "SAP no disponible"}
    
    try:
        df_sap = pd.read_excel(sap_files[0])
        df_pos = df_sap[(df_sap["UNIDAD"]=="FARMACIAS") & (df_sap["POS"]==pos)]
        if df_pos.empty:
            return {"mensaje": "Sin registros en SAP"}
        stock_por_dia = df_pos.groupby("DIA")["STOCK"].sum()
        dias_con_stock = stock_por_dia[stock_por_dia > 0]
        if dias_con_stock.empty:
            return {"mensaje": "Sin stock registrado"}
        ultimo_dia = dias_con_stock.index.max()
        stock_dia = df_pos[df_pos["DIA"]==ultimo_dia][["PRODUCTO","STOCK","IDNEPTUNO"]].copy()
        stock_dia = stock_dia.sort_values("STOCK", ascending=False)
        return {
            "fecha": str(ultimo_dia),
            "total_productos": len(stock_dia),
            "detalle_stock": stock_dia[["PRODUCTO","STOCK"]].to_dict("records")[:15],
            "sin_stock": stock_dia[stock_dia["STOCK"]==0]["PRODUCTO"].tolist()[:5],
            "bajo_stock": stock_dia[(stock_dia["STOCK"]>0) & (stock_dia["STOCK"]<=3)][["PRODUCTO","STOCK"]].to_dict("records")[:5],
            "con_stock_ok": stock_dia[stock_dia["STOCK"]>3][["PRODUCTO","STOCK"]].to_dict("records")[:5]
        }
    except Exception as e:
        return {"error": f"Error: {str(e)[:50]}"}

# ── ENDPOINTS DE AUTENTICACIÓN ──

@app.route("/login", methods=["POST", "OPTIONS"])
def login():
    """Login con usuario y contraseña"""
    if request.method == "OPTIONS":
        return "", 204
    
    data = request.json
    usuario = data.get("usuario", "").strip()
    contraseña = data.get("contraseña", "").strip()
    
    if not usuario or not contraseña:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400
    
    # Validar credenciales
    if usuario not in USUARIOS:
        return jsonify({"error": "Usuario no existe"}), 401
    
    # Comparar contraseña encriptada
    contraseña_encriptada = hashlib.sha256(contraseña.encode()).hexdigest()
    if USUARIOS[usuario] != contraseña_encriptada:
        return jsonify({"error": "Contraseña incorrecta"}), 401
    
    # Generar token (válido por 24 horas)
    token = hashlib.sha256(f"{usuario}{time.time()}".encode()).hexdigest()
    SESIONES_ACTIVAS[token] = time.time() + 86400  # 24 horas
    
    return jsonify({
        "exito": True,
        "token": token,
        "usuario": usuario,
        "mensaje": f"Bienvenido {usuario}"
    }), 200

@app.route("/logout", methods=["POST"])
def logout():
    """Cerrar sesión"""
    data = request.json
    token = data.get("token", "")
    
    if token in SESIONES_ACTIVAS:
        del SESIONES_ACTIVAS[token]
    
    return jsonify({"exito": True, "mensaje": "Sesión cerrada"}), 200

@app.route("/verificar_token", methods=["POST"])
def verificar_token_endpoint():
    """Verificar si un token sigue siendo válido"""
    data = request.json
    token = data.get("token", "")
    
    if verificar_token(token):
        return jsonify({"valido": True}), 200
    else:
        return jsonify({"valido": False}), 401

# ── ENDPOINTS DEL CHAT (CON PROTECCIÓN) ──

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "cache_loaded": _df_cache is not None,
        "timestamp": time.time()
    }), 200

@app.route("/grupos", methods=["GET"])
def get_grupos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verificar_token(token):
        return jsonify({"error": "No autorizado. Token inválido o expirado."}), 401
    
    df = cargar_datos()
    if df.empty:
        return jsonify({"error": "Sin datos"}), 500
    farm = df[df["UNIDAD"]=="FARMACIAS"]
    grupos = farm.groupby("GRUPOPDV").agg(
        ventas=("VENTA NETA RECUPERO","sum"),
        pos_count=("POS","nunique")
    ).reset_index().sort_values("ventas", ascending=False)
    return jsonify([{
        "grupo": r["GRUPOPDV"],
        "ventas": round(float(r["ventas"]),2),
        "total_pos": int(r["pos_count"])
    } for _, r in grupos.iterrows()]), 200

@app.route("/farmacias/<grupo>", methods=["GET"])
def get_farmacias_por_grupo(grupo):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verificar_token(token):
        return jsonify({"error": "No autorizado"}), 401
    
    df = cargar_datos()
    if df.empty:
        return jsonify({"error": "Sin datos"}), 500
    farm = df[df["UNIDAD"]=="FARMACIAS"]
    grupo_decoded = grupo.replace("_", " ")
    farm_grupo = farm[farm["GRUPOPDV"].str.lower() == grupo_decoded.lower()]
    if farm_grupo.empty:
        farm_grupo = farm[farm["GRUPOPDV"].str.lower().str.contains(grupo_decoded.lower(), na=False)]
    por_pos = farm_grupo.groupby("POS").agg(
        ventas=("VENTA NETA RECUPERO","sum"),
        unidades=("UNIDADES_ROTADAS","sum")
    ).reset_index().sort_values("ventas", ascending=False)
    return jsonify([{
        "pos": r["POS"],
        "ventas": round(float(r["ventas"]),2),
        "unidades": int(r["unidades"])
    } for _, r in por_pos.iterrows()]), 200

@app.route("/buscar_pos", methods=["GET"])
def buscar_pos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verificar_token(token):
        return jsonify({"error": "No autorizado"}), 401
    
    texto = request.args.get("q","").strip().lower()
    if len(texto) < 2:
        return jsonify([]), 200
    df = cargar_datos()
    if df.empty:
        return jsonify([]), 500
    farm = df[df["UNIDAD"]=="FARMACIAS"]
    todos_pos = farm["POS"].dropna().unique()
    matches = [p for p in todos_pos if texto in str(p).lower()][:30]
    ventas = farm[farm["POS"].isin(matches)].groupby("POS")["VENTA NETA RECUPERO"].sum()
    resultado = sorted([{"pos": p, "ventas": round(float(ventas.get(p,0)),2)} for p in matches],
                       key=lambda x: x["ventas"], reverse=True)
    return jsonify(resultado), 200

@app.route("/detalle_pos", methods=["POST"])
def detalle_pos():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verificar_token(token):
        return jsonify({"error": "No autorizado"}), 401
    
    data = request.json
    pos = data.get("pos","")
    if not pos:
        return jsonify({"error": "POS requerido"}), 400
    df = cargar_datos()
    if df.empty:
        return jsonify({"error": "Sin datos"}), 500
    farm = df[df["UNIDAD"]=="FARMACIAS"]
    datos_pos = farm[farm["POS"]==pos].copy()
    if datos_pos.empty:
        return jsonify({"error": f"No se encontró {pos}"}), 404
    venta_total = float(datos_pos["VENTA NETA RECUPERO"].sum())
    unidades = int(datos_pos["UNIDADES_ROTADAS"].sum())
    grupo = datos_pos["GRUPOPDV"].iloc[0]
    col_fecha = "DIA" if "DIA" in datos_pos.columns else "FECHA" if "FECHA" in datos_pos.columns else None
    if col_fecha:
        datos_pos["MES"] = datos_pos[col_fecha].astype(str).apply(parsear_mes_fecha)
    else:
        datos_pos["MES"] = "desconocido"
    tend = datos_pos.groupby("MES")["VENTA NETA RECUPERO"].sum().to_dict()
    tend = {k: round(float(v), 2) for k, v in tend.items()}
    top_prods = datos_pos.groupby("PRODUCTO")["VENTA NETA RECUPERO"].sum().nlargest(5).to_dict()
    top_prods = {k: round(float(v), 2) for k, v in top_prods.items()}
    stock_info = obtener_stock_pos(pos, df)
    venta_total_farm = float(farm["VENTA NETA RECUPERO"].sum())
    pct = (venta_total / venta_total_farm * 100) if venta_total_farm > 0 else 0
    return jsonify({
        "pos": pos,
        "grupo_pdv": grupo,
        "venta_total": round(venta_total, 2),
        "unidades_rotadas": unidades,
        "pct_del_total": round(pct, 2),
        "tendencia_mensual": tend,
        "top_5_productos": top_prods,
        "stock_info": stock_info
    }), 200

@app.route("/chat", methods=["POST", "OPTIONS"])
def chat():
    if request.method == "OPTIONS":
        return "", 204
    
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not verificar_token(token):
        return jsonify({"error": "No autorizado. Inicia sesión primero."}), 401
    
    data = request.json
    pregunta = data.get("pregunta","").strip()
    contexto_pos = data.get("contexto_pos", None)
    
    if not pregunta:
        return jsonify({"error": "Pregunta vacía"}), 400
    
    df = cargar_datos()
    if df.empty:
        return jsonify({"error": "Base de datos no cargada"}), 500

    if contexto_pos:
        farm = df[df["UNIDAD"]=="FARMACIAS"]
        datos_pos = farm[farm["POS"]==contexto_pos].copy()
        if datos_pos.empty:
            return jsonify({"error": f"Farmacia {contexto_pos} no encontrada"}), 404
        venta_total = float(datos_pos["VENTA NETA RECUPERO"].sum())
        col_fecha = "DIA" if "DIA" in datos_pos.columns else "FECHA" if "FECHA" in datos_pos.columns else None
        if col_fecha:
            datos_pos["MES"] = datos_pos[col_fecha].astype(str).apply(parsear_mes_fecha)
        else:
            datos_pos["MES"] = "desconocido"
        tend = datos_pos.groupby("MES")["VENTA NETA RECUPERO"].sum().to_dict()
        tend = {k: round(float(v), 2) for k, v in tend.items()}
        top_prods = datos_pos.groupby("PRODUCTO")["VENTA NETA RECUPERO"].sum().nlargest(5).to_dict()
        top_prods = {k: round(float(v), 2) for k, v in top_prods.items()}
        stock_info = obtener_stock_pos(contexto_pos, df)
        venta_total_farm = float(farm["VENTA NETA RECUPERO"].sum())
        pct = (venta_total / venta_total_farm * 100) if venta_total_farm > 0 else 0
        contexto = {
            "pos": contexto_pos,
            "grupo": datos_pos["GRUPOPDV"].iloc[0] if len(datos_pos) > 0 else "N/A",
            "venta_total": round(venta_total, 2),
            "pct_total": round(pct, 2),
            "tendencia": tend,
            "top_productos": top_prods,
            "stock": stock_info
        }
    else:
        farm = df[df["UNIDAD"]=="FARMACIAS"]
        dist = df[df["UNIDAD"]=="DISTRIBUCION DIFARE"]
        contexto = {
            "venta_farmacias": round(float(farm["VENTA NETA RECUPERO"].sum()), 2),
            "venta_distribucion": round(float(dist["VENTA NETA RECUPERO"].sum()), 2),
            "top_farmacias": {k: round(float(v), 2) for k, v in farm.groupby("POS")["VENTA NETA RECUPERO"].sum().nlargest(5).to_dict().items()},
            "top_marcas": {k: round(float(v), 2) for k, v in df[df["UNIDAD"]!="DIFARE S.A."].groupby("MARCA")["VENTA NETA RECUPERO"].sum().nlargest(5).to_dict().items()}
        }

    prompt = f"""Eres el asistente comercial Difare Nexus de Genommalab Ecuador.
Datos reales DIFARE Ecuador enero-marzo 2026.
Responde conciso, ejecutivo, máximo 5 líneas. Usa emojis. Destaca números con **negrita**.

IMPORTANTE: Solo puedes responder sobre la farmacia actualmente seleccionada.
Si el usuario pregunta por OTRA farmacia diferente, responde:
"Para consultar otra farmacia, usa el botón 🏠 Inicio para seleccionarla."

Farmacia actualmente seleccionada: {contexto.get('pos', 'GENERAL')}
Datos disponibles: {contexto}
Pregunta: {pregunta}

Responde en español, práctico para vendedor en campo."""

    try:
        resp = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=300,
            messages=[{"role":"user","content":prompt}]
        )
        return jsonify({
            "respuesta": resp.content[0].text,
            "contexto_tipo": "farmacia" if contexto_pos else "general",
            "timestamp": time.time()
        }), 200
    except Exception as e:
        return jsonify({
            "error": f"Error Claude API: {str(e)[:100]}",
            "respuesta": "Disculpa, hubo un error. Intenta de nuevo."
        }), 500

# ── PARA VERCEL ──
if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 DIFARE NEXUS Chat Server v2 (CON AUTENTICACIÓN)")
    print("="*60)
    cargar_datos_async()
    print("\n✅ Servidor listo")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

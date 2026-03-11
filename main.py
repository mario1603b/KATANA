import customtkinter as ctk
from tkinter import filedialog, messagebox, ttk
import requests
import urllib3
import time
import re
import traceback 
import os
from PIL import Image

# Desactivar advertencias de certificados SSL para las conexiones API al firewall
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ==========================================
# CONFIGURACIÓN ESTILO macOS
# ==========================================
ctk.set_appearance_mode("Dark")

MAC_BG = "#1C1C1E"          
MAC_PANEL = "#2C2C2E"       
MAC_HOVER = "#48484A"       
MAC_BLUE = "#0A84FF"        
MAC_BLUE_HOVER = "#0060C0"
MAC_GREEN = "#32D74B"       
MAC_GREEN_HOVER = "#24A136"
MAC_RED = "#FF453A"
MAC_RED_HOVER = "#C9342B"
MAC_TEXT = "#FFFFFF"
MAC_TEXT_MUTED = "#AEAEB2"  

class SophosAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("KATANA - Threat Intelligence & Active Defense")
        self.root.geometry("1200x750")
        self.root.configure(fg_color=MAC_BG)
        
        self.archivo_seleccionado = None
        self.df_mapa = None 
        self.df_ips_global = None 
        self.modo_oscuro = True   

        self.cargar_iconos_mac()

        # ==========================================
        # BARRA LATERAL (SIDEBAR)
        # ==========================================
        self.sidebar = ctk.CTkFrame(self.root, width=260, fg_color=MAC_PANEL, corner_radius=0)
        self.sidebar.pack(side=ctk.LEFT, fill=ctk.Y)
        self.sidebar.pack_propagate(False) 
        
        self.lbl_logo = ctk.CTkLabel(self.sidebar, text="KATANA", font=("-apple-system", 28, "bold"), text_color=MAC_BLUE)
        self.lbl_logo.pack(pady=(40, 0))
        self.lbl_sub = ctk.CTkLabel(self.sidebar, text="Ultimate Edition", font=("-apple-system", 13), text_color=MAC_TEXT_MUTED)
        self.lbl_sub.pack(pady=(0, 40))

        self.btn_seleccionar = ctk.CTkButton(self.sidebar, text="  1. Seleccionar Log", image=self.ic_folder, command=self.seleccionar_archivo, 
                                             fg_color="#3A3A3C", hover_color=MAC_HOVER, text_color=MAC_TEXT, 
                                             font=("-apple-system", 14, "bold"), width=220, height=45, corner_radius=8, anchor="w")
        self.btn_seleccionar.pack(pady=(10, 5), padx=20)
        
        self.lbl_archivo = ctk.CTkLabel(self.sidebar, text="Ningún archivo", font=("-apple-system", 12), text_color=MAC_TEXT_MUTED)
        self.lbl_archivo.pack(pady=(0, 30), padx=20)

        self.btn_analizar = ctk.CTkButton(self.sidebar, text="  2. Iniciar Análisis", image=self.ic_bolt, command=self.analizar_datos, state=ctk.DISABLED, 
                                          fg_color=MAC_BLUE, hover_color=MAC_BLUE_HOVER, text_color="white", 
                                          font=("-apple-system", 15, "bold"), width=220, height=50, corner_radius=8, anchor="w")
        self.btn_analizar.pack(pady=10, padx=20)

        self.btn_tema = ctk.CTkButton(self.sidebar, text="  Apariencia", image=self.ic_theme, command=self.toggle_tema, 
                                      fg_color="#3A3A3C", hover_color=MAC_HOVER, text_color=MAC_TEXT, 
                                      font=("-apple-system", 13, "bold"), width=220, height=40, corner_radius=8, anchor="w")
        self.btn_tema.pack(side=ctk.BOTTOM, pady=30, padx=20)

        # ==========================================
        # CONTENIDO PRINCIPAL
        # ==========================================
        self.main_content = ctk.CTkFrame(self.root, fg_color=MAC_BG, corner_radius=0)
        self.main_content.pack(side=ctk.LEFT, fill=ctk.BOTH, expand=True, padx=25, pady=25)

        # --- Panel Izquierdo (Tabla) ---
        self.frame_izq = ctk.CTkFrame(self.main_content, fg_color=MAC_PANEL, corner_radius=12, width=340)
        self.frame_izq.pack(side=ctk.LEFT, fill=ctk.Y, expand=False)
        self.frame_izq.pack_propagate(False)

        self.lbl_titulo_izq = ctk.CTkLabel(self.frame_izq, text="Direcciones IP Detectadas", font=("-apple-system", 15, "bold"), text_color=MAC_TEXT)
        self.lbl_titulo_izq.pack(pady=(20, 10), padx=20, anchor="w")

        self.style = ttk.Style()
        self.aplicar_estilo_tabla()
        
        columnas = ("Pais", "IP", "Intentos")
        self.tree = ttk.Treeview(self.frame_izq, columns=columnas, show="headings", height=20)
        self.tree.heading("Pais", text="País")
        self.tree.heading("IP", text="IP")
        self.tree.heading("Intentos", text="Ataques")
        self.tree.column("Pais", width=90)
        self.tree.column("IP", width=130)
        self.tree.column("Intentos", width=80, anchor=ctk.CENTER)
        self.tree.pack(fill=ctk.BOTH, expand=True, padx=15, pady=(0, 15))

        # --- Panel Derecho (Pestañas) ---
        self.tabview = ctk.CTkTabview(self.main_content, fg_color=MAC_PANEL, 
                                      segmented_button_fg_color="#1C1C1E",         
                                      segmented_button_selected_color=MAC_BLUE,    
                                      segmented_button_selected_hover_color=MAC_BLUE_HOVER, 
                                      segmented_button_unselected_color="#3A3A3C", 
                                      segmented_button_unselected_hover_color=MAC_HOVER, 
                                      corner_radius=12, text_color=MAC_TEXT)
        self.tabview.pack(side=ctk.RIGHT, fill=ctk.BOTH, expand=True, padx=(25, 0))
        
        self.tabview._segmented_button.configure(font=("-apple-system", 13, "bold"))

        self.tab_barras = self.tabview.add("Geografía")
        self.tab_usuarios = self.tabview.add("Usuarios")
        self.tab_mapa = self.tabview.add("Inteligencia")
        self.tab_mitigacion = self.tabview.add("Mitigación (AEGIS)") 

        self.configurar_pestana_mapa()
        self.configurar_pestana_mitigacion()

    def configurar_pestana_mapa(self):
        self.lbl_mapa_1 = ctk.CTkLabel(self.tab_mapa, text="Mapa Global de Amenazas", font=("-apple-system", 22, "bold"), text_color=MAC_TEXT)
        self.lbl_mapa_1.pack(pady=(80, 5))
        self.lbl_mapa_2 = ctk.CTkLabel(self.tab_mapa, text="Genera una vista topológica en alta resolución.\nSe abrirá de forma segura en tu navegador.", font=("-apple-system", 14), text_color=MAC_TEXT_MUTED)
        self.lbl_mapa_2.pack(pady=(0, 30))
        self.btn_mapa = ctk.CTkButton(self.tab_mapa, text=" Lanzar Mapa Interactivo", image=self.ic_map, command=self.abrir_mapa, state=ctk.DISABLED, 
                                      fg_color=MAC_GREEN, hover_color=MAC_GREEN_HOVER, text_color="white", 
                                      font=("-apple-system", 15, "bold"), height=50, corner_radius=8, width=250)
        self.btn_mapa.pack(pady=10)

    def configurar_pestana_mitigacion(self):
        # Título
        ctk.CTkLabel(self.tab_mitigacion, text="Motor de Defensa Activa (AEGIS)", font=("-apple-system", 18, "bold"), text_color=MAC_RED).pack(pady=(15, 5))
        ctk.CTkLabel(self.tab_mitigacion, text="Inyecta objetos IP en el Firewall automáticamente mediante API.", font=("-apple-system", 12), text_color=MAC_TEXT_MUTED).pack(pady=(0, 15))

        # Marco del Formulario
        form_frame = ctk.CTkFrame(self.tab_mitigacion, fg_color="#1C1C1E", corner_radius=8)
        form_frame.pack(fill=ctk.X, padx=20, pady=5)

        # Fila 1: IP y Puerto
        row1 = ctk.CTkFrame(form_frame, fg_color="transparent")
        row1.pack(fill=ctk.X, padx=15, pady=(15, 5))
        ctk.CTkLabel(row1, text="IP Firewall:", width=80, anchor="w").pack(side=ctk.LEFT)
        self.entry_fw_ip = ctk.CTkEntry(row1, width=140, placeholder_text="Ej: 192.168.1.1")
        self.entry_fw_ip.pack(side=ctk.LEFT, padx=(0, 20))
        
        ctk.CTkLabel(row1, text="Puerto:", width=60, anchor="w").pack(side=ctk.LEFT)
        self.entry_fw_port = ctk.CTkEntry(row1, width=70)
        self.entry_fw_port.insert(0, "4444")
        self.entry_fw_port.pack(side=ctk.LEFT)

        # Fila 2: Usuario y Contraseña
        row2 = ctk.CTkFrame(form_frame, fg_color="transparent")
        row2.pack(fill=ctk.X, padx=15, pady=5)
        ctk.CTkLabel(row2, text="Usuario API:", width=80, anchor="w").pack(side=ctk.LEFT)
        self.entry_fw_user = ctk.CTkEntry(row2, width=140, placeholder_text="admin")
        self.entry_fw_user.pack(side=ctk.LEFT, padx=(0, 20))
        
        ctk.CTkLabel(row2, text="Password:", width=60, anchor="w").pack(side=ctk.LEFT)
        self.entry_fw_pass = ctk.CTkEntry(row2, width=140, show="*")
        self.entry_fw_pass.pack(side=ctk.LEFT)

        # Fila 3: Configuración de Bloqueo
        row3 = ctk.CTkFrame(form_frame, fg_color="transparent")
        row3.pack(fill=ctk.X, padx=15, pady=(5, 15))
        ctk.CTkLabel(row3, text="Bloquear:", width=80, anchor="w").pack(side=ctk.LEFT)
        self.combo_limite = ctk.CTkOptionMenu(row3, values=["Top 10 IPs", "Top 50 IPs", "Top 100 IPs"], width=140, fg_color=MAC_PANEL, button_color="#3A3A3C", button_hover_color=MAC_HOVER)
        self.combo_limite.pack(side=ctk.LEFT)

        # Botón de Ejecución
        self.btn_aegis = ctk.CTkButton(self.tab_mitigacion, text=" INYECTAR REGLAS EN FIREWALL", command=self.ejecutar_aegis, state=ctk.DISABLED, 
                                      fg_color=MAC_RED, hover_color=MAC_RED_HOVER, text_color="white", 
                                      font=("-apple-system", 14, "bold"), height=40, corner_radius=8)
        self.btn_aegis.pack(pady=15)

        # Consola de salida
        self.txt_consola = ctk.CTkTextbox(self.tab_mitigacion, fg_color="#000000", text_color="#32D74B", font=("Courier", 11), corner_radius=8)
        self.txt_consola.pack(fill=ctk.BOTH, expand=True, padx=20, pady=(0, 20))
        self.txt_consola.insert("0.0", "> AEGIS Standby. Esperando análisis de log...\n")
        self.txt_consola.configure(state="disabled")

    def cargar_iconos_mac(self):
        carpeta_iconos = ".iconos_mac"
        if not os.path.exists(carpeta_iconos): os.makedirs(carpeta_iconos)

        iconos_urls = {
            "folder": "https://img.icons8.com/ios/50/ffffff/mac-folder.png",
            "bolt": "https://img.icons8.com/ios/50/ffffff/flash-on.png",
            "theme": "https://img.icons8.com/ios/50/ffffff/sun--v1.png",
            "map": "https://img.icons8.com/ios/50/ffffff/map.png"
        }

        self.iconos_cargados = {}
        for nombre, url in iconos_urls.items():
            ruta = os.path.join(carpeta_iconos, f"{nombre}.png")
            try:
                if not os.path.exists(ruta):
                    r = requests.get(url, timeout=5)
                    with open(ruta, 'wb') as f: f.write(r.content)
                img = Image.open(ruta)
                self.iconos_cargados[nombre] = ctk.CTkImage(light_image=img, dark_image=img, size=(22, 22))
            except: self.iconos_cargados[nombre] = None 

        self.ic_folder = self.iconos_cargados.get("folder")
        self.ic_bolt = self.iconos_cargados.get("bolt")
        self.ic_theme = self.iconos_cargados.get("theme")
        self.ic_map = self.iconos_cargados.get("map")

    def aplicar_estilo_tabla(self):
        bg_color = MAC_PANEL if self.modo_oscuro else "#FFFFFF"
        fg_color = MAC_TEXT if self.modo_oscuro else "#000000"
        head_bg = "#3A3A3C" if self.modo_oscuro else "#E5E5EA"
        
        self.style.theme_use("default")
        self.style.configure("Treeview", background=bg_color, foreground=fg_color, rowheight=35, fieldbackground=bg_color, borderwidth=0, font=("-apple-system", 11))
        self.style.configure("Treeview.Heading", background=head_bg, foreground=fg_color, font=("-apple-system", 12, "bold"), borderwidth=0, padding=8)
        self.style.map("Treeview", background=[('selected', MAC_BLUE)], foreground=[('selected', 'white')])

    def toggle_tema(self):
        self.modo_oscuro = not self.modo_oscuro
        if self.modo_oscuro:
            ctk.set_appearance_mode("Dark")
            self.root.configure(fg_color=MAC_BG)
            self.sidebar.configure(fg_color=MAC_PANEL)
            self.main_content.configure(fg_color=MAC_BG)
            self.frame_izq.configure(fg_color=MAC_PANEL)
            self.btn_seleccionar.configure(fg_color="#3A3A3C", hover_color=MAC_HOVER)
            self.btn_tema.configure(fg_color="#3A3A3C", hover_color=MAC_HOVER)
            self.tabview.configure(fg_color=MAC_PANEL, segmented_button_fg_color="#1C1C1E", segmented_button_unselected_color="#3A3A3C", segmented_button_unselected_hover_color=MAC_HOVER)
        else:
            ctk.set_appearance_mode("Light")
            self.root.configure(fg_color="#F2F2F7")
            self.sidebar.configure(fg_color="#FFFFFF")
            self.main_content.configure(fg_color="#F2F2F7")
            self.frame_izq.configure(fg_color="#FFFFFF")
            self.btn_seleccionar.configure(fg_color="#E5E5EA", hover_color="#D1D1D6", text_color="black")
            self.btn_tema.configure(fg_color="#E5E5EA", hover_color="#D1D1D6", text_color="black")
            self.tabview.configure(fg_color="#FFFFFF", segmented_button_fg_color="#F2F2F7", segmented_button_unselected_color="#E5E5EA", segmented_button_unselected_hover_color="#D1D1D6", text_color="black")
        
        self.aplicar_estilo_tabla()
        if self.df_ips_global is not None: self.actualizar_graficos_post_tema()

    def escribir_consola(self, texto):
        self.txt_consola.configure(state="normal")
        self.txt_consola.insert("end", texto + "\n")
        self.txt_consola.see("end")
        self.txt_consola.configure(state="disabled")
        self.root.update()

    def mostrar_alerta(self, titulo, mensaje, tipo="error"):
        if tipo == "error": messagebox.showerror(titulo, mensaje)
        elif tipo == "warning": messagebox.showwarning(titulo, mensaje)
        else: messagebox.showinfo(titulo, mensaje)

    def seleccionar_archivo(self):
        archivo = filedialog.askopenfilename(title="Seleccionar archivo Log", filetypes=(("Archivos CSV", "*.csv"), ("Todos los archivos", "*.*")))
        if archivo:
            self.archivo_seleccionado = archivo
            nombre = archivo.split("/")[-1]
            if len(nombre) > 25: nombre = nombre[:22] + "..."
            self.lbl_archivo.configure(text=nombre, text_color=MAC_BLUE)
            self.btn_analizar.configure(state=ctk.NORMAL)

    def analizar_datos(self):
        self.btn_analizar.configure(text="  Cargando motores...", state=ctk.DISABLED)
        self.btn_mapa.configure(state=ctk.DISABLED)
        self.btn_aegis.configure(state=ctk.DISABLED)
        self.root.update()

        try:
            import pandas as pd
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            
            try: df = pd.read_csv(self.archivo_seleccionado, sep=None, engine='python')
            except: df = pd.read_csv(self.archivo_seleccionado, sep=',')
            
            df.columns = df.columns.str.strip()
            df['Fila_Completa'] = df.fillna('').astype(str).apply(lambda row: ' '.join(row), axis=1)
            
            df['IP_Atacante'] = df['Fila_Completa'].str.extract(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
            df_ips = df.dropna(subset=['IP_Atacante']).copy()

            if df_ips.empty:
                self.mostrar_alerta("Aviso", "No se encontraron ataques.", "warning")
                self.reset_boton()
                return

            df_ips['Usuario'] = df_ips['Fila_Completa'].str.extract(r"User\s+([^\s]+)\s+failed\s+to\s+login", flags=re.IGNORECASE)
            if 'Username' in df_ips.columns: df_ips['Usuario'] = df_ips['Usuario'].combine_first(df_ips['Username'])
            df_ips['Usuario'] = df_ips['Usuario'].replace({'': 'Desconocido', 'NaN': 'Desconocido', 'nan': 'Desconocido', 'N/A': 'Desconocido'}).fillna('Desconocido')

            ips_unicas = df_ips['IP_Atacante'].unique().tolist()
            paises = {}
            total_ips = len(ips_unicas)
            
            for i in range(0, total_ips, 100):
                lote = ips_unicas[i:i+100]
                self.btn_analizar.configure(text=f"  API Lote {min(i+100, total_ips)}/{total_ips}")
                self.root.update()
                try:
                    data = [{"query": ip, "fields": "country"} for ip in lote]
                    response = requests.post("http://ip-api.com/batch", json=data, timeout=10)
                    if response.status_code == 200:
                        for ip, info in zip(lote, response.json()): paises[ip] = info.get('country', 'Unknown')
                    else:
                        for ip in lote: paises[ip] = 'Unknown'
                except:
                    for ip in lote: paises[ip] = 'Error Red'
                time.sleep(1.2)

            df_ips['Pais'] = df_ips['IP_Atacante'].map(paises)
            self.df_ips_global = df_ips 

            self.actualizar_tabla()
            self.actualizar_graficos_post_tema()
            
            self.df_mapa = df_ips.groupby('Pais').size().reset_index(name='Total_Ataques')
            df_ips[['Time', 'IP_Atacante', 'Pais', 'Usuario', 'Fila_Completa']].to_csv('Resultado_KATANA.csv', index=False)
            
            self.btn_mapa.configure(state=ctk.NORMAL)
            self.btn_aegis.configure(state=ctk.NORMAL) 
            self.escribir_consola(f"> Análisis completado. Detectadas {total_ips} IPs únicas listas para mitigar.")
            
            self.mostrar_alerta("Completado", f"Análisis finalizado exitosamente.\n{len(df_ips)} intentos procesados.", "info")

        except Exception as e:
            traceback.print_exc() 
            self.mostrar_alerta("Error Crítico", f"{str(e)}", "error")
        
        self.reset_boton()

    def actualizar_tabla(self):
        conteo_ips = self.df_ips_global.groupby(['Pais', 'IP_Atacante']).size().reset_index(name='Intentos')
        conteo_ips = conteo_ips.sort_values(by=['Pais', 'Intentos'], ascending=[True, False])
        for row in self.tree.get_children(): self.tree.delete(row)
        for index, row in conteo_ips.iterrows():
            self.tree.insert("", "end", values=(row['Pais'], row['IP_Atacante'], row['Intentos']))

    def actualizar_graficos_post_tema(self):
        import matplotlib.pyplot as plt
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        
        bg_color = MAC_PANEL if self.modo_oscuro else '#FFFFFF'
        text_color = MAC_TEXT if self.modo_oscuro else '#000000'
        
        for widget in self.tab_barras.winfo_children(): widget.destroy()
        fig1, ax1 = plt.subplots(figsize=(6, 4))
        fig1.patch.set_facecolor(bg_color); ax1.set_facecolor(bg_color)
        
        conteo_paises = self.df_ips_global['Pais'].value_counts()
        conteo_paises.head(15).plot(kind='bar', ax=ax1, color="#FF453A", edgecolor=bg_color, alpha=0.9)
        ax1.set_title('Top Origen de Ataques', fontweight='bold', color=text_color, pad=15)
        ax1.tick_params(colors=text_color)
        for spine in ax1.spines.values(): spine.set_edgecolor(bg_color)
        
        plt.xticks(rotation=45, ha='right')
        fig1.tight_layout()
        canvas1 = FigureCanvasTkAgg(fig1, master=self.tab_barras)
        canvas1.draw()
        canvas1.get_tk_widget().pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)

        for widget in self.tab_usuarios.winfo_children(): widget.destroy()
        fig2, ax2 = plt.subplots(figsize=(6, 4))
        fig2.patch.set_facecolor(bg_color); ax2.set_facecolor(bg_color)
        
        conteo_usuarios = self.df_ips_global[self.df_ips_global['Usuario'] != 'Desconocido']['Usuario'].value_counts().head(10)
        if not conteo_usuarios.empty:
            conteo_usuarios.sort_values().plot(kind='barh', ax=ax2, color="#FF9F0A", edgecolor=bg_color, alpha=0.9)
            ax2.set_title('Top Cuentas Comprometidas', fontweight='bold', color=text_color, pad=15)
            ax2.tick_params(colors=text_color)
            for spine in ax2.spines.values(): spine.set_edgecolor(bg_color)
            
            fig2.tight_layout()
            canvas2 = FigureCanvasTkAgg(fig2, master=self.tab_usuarios)
            canvas2.draw()
            canvas2.get_tk_widget().pack(fill=ctk.BOTH, expand=True, padx=10, pady=10)

    def abrir_mapa(self):
        if self.df_mapa is None or self.df_mapa.empty: return
        
        import plotly.express as px
        import webbrowser
        import warnings
        import os
        
        # Silenciamos el aviso molesto de Plotly sobre "country names"
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        fig = px.choropleth(
            self.df_mapa, locations="Pais", locationmode="country names", color="Total_Ataques", hover_name="Pais",
            color_continuous_scale=px.colors.sequential.Reds, title="Global Threat Intelligence (AEGIS)"
        )
        fig.update_layout(geo=dict(showframe=False, showcoastlines=True, projection_type='equirectangular', bgcolor=MAC_BG), 
                          paper_bgcolor=MAC_BG, font=dict(color='white'))
        
        archivo_html = os.path.abspath("mapa_katana.html")
        fig.write_html(archivo_html)
        
        # Lanzamos el navegador de forma segura
        webbrowser.open(f"file://{archivo_html}")

    # ==========================================
    # MOTOR AEGIS (DEFENSA ACTIVA)
    # ==========================================
    def ejecutar_aegis(self):
        if self.df_ips_global is None or self.df_ips_global.empty: return

        fw_ip = self.entry_fw_ip.get().strip()
        fw_port = self.entry_fw_port.get().strip()
        fw_user = self.entry_fw_user.get().strip()
        fw_pass = self.entry_fw_pass.get().strip()

        if not all([fw_ip, fw_port, fw_user, fw_pass]):
            self.mostrar_alerta("Faltan Datos", "Por favor, rellena todas las credenciales del Firewall.", "warning")
            return

        limite_str = self.combo_limite.get()
        limite = int(limite_str.split(" ")[1])

        top_ips = self.df_ips_global['IP_Atacante'].value_counts().head(limite).index.tolist()

        respuesta = messagebox.askyesno("Confirmar Mitigación", f"¿Estás seguro de que deseas inyectar {len(top_ips)} IPs en el firewall {fw_ip}?\nEsta acción creará objetos de red reales en Sophos.")
        if not respuesta: return

        self.btn_aegis.configure(state=ctk.DISABLED, text=" INYECTANDO REGLAS...")
        self.escribir_consola(f"\n[+] Iniciando despliegue AEGIS en {fw_ip}:{fw_port}...")
        self.escribir_consola(f"[+] Objetivo: Bloquear las {len(top_ips)} IPs más agresivas.")
        
        api_url = f"https://{fw_ip}:{fw_port}/webconsole/APIController"
        exitos = 0

        for ip in top_ips:
            nombre_objeto = f"AEGIS_{ip.replace('.', '_')}"
            xml_request = f"""
            <Request>
                <Login>
                    <Username>{fw_user}</Username>
                    <Password>{fw_pass}</Password>
                </Login>
                <Set>
                    <IPHost>
                        <Name>{nombre_objeto}</Name>
                        <IPFamily>IPv4</IPFamily>
                        <HostType>IP</HostType>
                        <IPAddress>{ip}</IPAddress>
                    </IPHost>
                </Set>
            </Request>
            """
            self.escribir_consola(f"  -> Solicitando creación de objeto para IP {ip}...")
            try:
                data = {'reqxml': xml_request}
                res = requests.post(api_url, data=data, verify=False, timeout=5)
                
                if 'status="200"' in res.text or 'Configuration applied successfully' in res.text:
                    self.escribir_consola(f"     [OK] Objeto '{nombre_objeto}' creado.")
                    exitos += 1
                elif 'Validation Fault' in res.text or 'already exists' in res.text:
                    self.escribir_consola(f"     [WARN] El objeto ya existía en el firewall.")
                elif 'Authentication Failure' in res.text:
                    self.escribir_consola(f"     [ERROR] Credenciales inválidas o API deshabilitada.")
                    break 
                else:
                    self.escribir_consola(f"     [ERROR] Respuesta inesperada del firewall.")
            except Exception as e:
                self.escribir_consola(f"     [ERROR RED] No se pudo conectar: {str(e)}")
                break 
            
            time.sleep(0.5)

        self.escribir_consola(f"\n[+] OPERACIÓN FINALIZADA. {exitos}/{len(top_ips)} IPs inyectadas correctamente.")
        self.btn_aegis.configure(state=ctk.NORMAL, text=" INYECTAR REGLAS EN FIREWALL")

    def reset_boton(self):
        self.btn_analizar.configure(text="  Iniciar Análisis", state=ctk.NORMAL)

if __name__ == "__main__":
    app = ctk.CTk()
    gui = SophosAnalyzerApp(app)
    app.mainloop()
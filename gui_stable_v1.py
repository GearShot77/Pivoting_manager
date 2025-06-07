import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import time
import datetime
import queue
import os
import re
import json

from tkinter.scrolledtext import ScrolledText
import networkx as nx
import matplotlib.pyplot as plt


class SessionManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Pivoting Manager GUI")
        self.geometry("1200x700")

        self.sessions = {}
        self.session_id_counter = 0
        self.log_history = []
        self.log_filter = ""

        os.makedirs("proxychains_confs", exist_ok=True)
        os.makedirs("session_logs", exist_ok=True)

        self.create_widgets()
        self.after(2000, self.refresh_sessions)

    def create_widgets(self):
        frame_buttons = tk.Frame(self)
        frame_buttons.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)

        tk.Button(frame_buttons, text="Создать сессию", command=self.create_session_dialog).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Закрыть сессию", command=self.close_session_dialog).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Обновить", command=self.refresh_sessions).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Выполнить proxychains команду", command=self.run_proxychains_command).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Граф туннелей", command=self.show_graph).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Экспорт сессий", command=self.export_sessions).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_buttons, text="Импорт сессий", command=self.import_sessions).pack(side=tk.LEFT, padx=5)

        tk.Label(frame_buttons, text="Фильтр логов:").pack(side=tk.LEFT)
        self.filter_entry = tk.Entry(frame_buttons)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_entry.bind("<KeyRelease>", self.apply_log_filter)

        columns = ("ID", "PID", "IP", "PORT", "STARTED", "STATUS", "CONNECTED_TUNNELS", "PING")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, anchor=tk.CENTER)
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.log_text = ScrolledText(self, height=12, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, padx=5, pady=5)

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        full_msg = f"{timestamp} {message}"
        self.log_history.append(full_msg)

        if self.log_filter and self.log_filter.lower() not in full_msg.lower():
            return

        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, full_msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

        
        with open("session_logs/log.txt", "a") as f:
            f.write(full_msg + "\n")

    def apply_log_filter(self, event=None):
        self.log_filter = self.filter_entry.get().strip()
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        for entry in self.log_history:
            if not self.log_filter or self.log_filter.lower() in entry.lower():
                self.log_text.insert(tk.END, entry + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def create_session_dialog(self):
        dialog = tk.Toplevel(self)
        dialog.title("Создать сессию")

        tk.Label(dialog, text="IP:").grid(row=0, column=0, sticky=tk.E)
        ip_entry = tk.Entry(dialog)
        ip_entry.grid(row=0, column=1)

        tk.Label(dialog, text="PORT:").grid(row=1, column=0, sticky=tk.E)
        port_entry = tk.Entry(dialog)
        port_entry.grid(row=1, column=1)

        tk.Label(dialog, text="PING интервал:").grid(row=2, column=0, sticky=tk.E)
        ping_entry = tk.Entry(dialog)
        ping_entry.grid(row=2, column=1)
        ping_entry.insert(0, "10")

        tk.Label(dialog, text="Инструмент:").grid(row=3, column=0, sticky=tk.E)
        tool_combo = ttk.Combobox(dialog, values=["chisel", "ssh", "socat", "other"])
        tool_combo.set("chisel")
        tool_combo.grid(row=3, column=1)

        def on_create():
            ip = ip_entry.get().strip()
            port = port_entry.get().strip()
            try:
                ping_int = int(ping_entry.get().strip())
            except ValueError:
                messagebox.showerror("Ошибка", "Пинг интервал должен быть числом")
                return
            if not ip or not port or ping_int < 1:
                messagebox.showerror("Ошибка", "Проверьте IP, PORT и интервал пинга")
                return
            self.create_session(ip, port, ping_int)
            dialog.destroy()

        tk.Button(dialog, text="Создать", command=on_create).grid(row=4, column=1, columnspan=2, pady=5)

    def create_session(self, ip, port, ping_interval, sid=None, tunnels=None):
        if sid is None:
            self.session_id_counter += 1
            sid = self.session_id_counter
        else:
            if sid > self.session_id_counter:
                self.session_id_counter = sid

        self.log(f"Запускаем chisel server на {ip}:{port} (сессия {sid})")

        try:
            proc = subprocess.Popen(
                ["chisel", "server", "--reverse", "--host", ip, "--port", port],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
        except Exception as e:
            messagebox.showerror("Ошибка запуска", str(e))
            return

        session = {
            "proc": proc,
            "ip": ip,
            "port": port,
            "start_time": datetime.datetime.now(),
            "status": "RUNNING",
            "ping_interval": ping_interval,
            "ping_result": "-",
            "tunnels": tunnels if tunnels else [],
            "log_queue": queue.Queue(),
        }

        self.sessions[sid] = session

        threading.Thread(target=self.ping_loop, args=(sid,), daemon=True).start()
        threading.Thread(target=self.read_chisel_output, args=(sid,), daemon=True).start()

        self.create_proxychains_conf(sid, session["tunnels"])

        self.log(f"Сессия {sid} создана и chisel запущен")

    def ping_loop(self, sid):
        session = self.sessions.get(sid)
        if not session:
            return
        ip = session["ip"]
        interval = session["ping_interval"]

        while sid in self.sessions:
            if ip == "0.0.0.0" or not ip:
                session["ping_result"] = "N/A"
            else:
                try:
                    result = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True)
                    output = result.stdout
                    if "time=" in output:
                        match = re.search(r"time=([\d.]+)", output)
                        session["ping_result"] = match.group(1) + " ms" if match else "OK"
                    else:
                        session["ping_result"] = "Dead"
                except:
                    session["ping_result"] = "Error"
            time.sleep(interval)

    def read_chisel_output(self, sid):
        session = self.sessions.get(sid)
        if not session:
            return
        proc = session["proc"]

        for line in proc.stdout:
            line = line.strip()

            tun_match = re.search(r"session#(\d+): tun: (proxy#R:[^\s=]+)", line)
            if tun_match:
                tun = tun_match.group(2)
                if tun not in session["tunnels"]:
                    session["tunnels"].append(tun)
                    self.log(f"Клиент подключен к {sid} сессии: {line}")
                    self.create_proxychains_conf(sid, session["tunnels"])
            elif any(x in line for x in ["Fingerprint", "Reverse tunnelling enabled", "Listening on "]):
                continue
            else:
                self.log(line)

        session["status"] = "STOPPED"

    def create_proxychains_conf(self, sid, tunnels):
        path = f"proxychains_confs/session_{sid}.conf"
        try:
            with open(path, "w") as f:
                f.write("strict_chain\n[ProxyList]\n")
                for t in tunnels:
                    try:
                        parts = t.split(":")
                        if len(parts) >= 3:
                            port_part = parts[2]
                            port = port_part.split("=>")[0]
                            f.write(f"socks5 127.0.0.1 {port}\n")
                    except Exception:
                        continue
        except Exception as e:
            self.log(f"Ошибка при создании proxychains конфига: {e}")

    def refresh_sessions(self):
        self.tree.delete(*self.tree.get_children())
        for sid, s in self.sessions.items():
            pid = s["proc"].pid if s["proc"].poll() is None else "-"
            start = s["start_time"].strftime("%H:%M:%S")
            status = s["status"]
            tunnels_str = ", ".join(s["tunnels"])
            ping = s.get("ping_result", "-")
            self.tree.insert("", tk.END, values=(sid, pid, s["ip"], s["port"], start, status, tunnels_str, ping))
        self.after(3000, self.refresh_sessions)

    def close_session_dialog(self):
        sid = self.get_selected_session_id()
        if sid is None:
            messagebox.showwarning("Внимание", "Выберите сессию для закрытия")
            return
        self.close_session(sid)

    def close_session(self, sid):
        session = self.sessions.get(sid)
        if not session:
            return
        proc = session["proc"]
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)
        self.log(f"Сессия {sid} остановлена")
        del self.sessions[sid]
        self.refresh_sessions()

    def get_selected_session_id(self):
        selected = self.tree.selection()
        if not selected:
            return None
        item = self.tree.item(selected[0])
        sid = item["values"][0]
        return sid

    def run_proxychains_command(self):
        sid = self.get_selected_session_id()
        if sid is None:
            messagebox.showwarning("Внимание", "Выберите сессию")
            return

        dialog = tk.Toplevel(self)
        dialog.title("Выполнить команду через proxychains")

        tk.Label(dialog, text="Команда:").pack()
        cmd_entry = tk.Entry(dialog, width=80)
        cmd_entry.pack()

        output_text = ScrolledText(dialog, height=15)
        output_text.pack()

        def run_cmd():
            cmd = cmd_entry.get().strip()
            if not cmd:
                messagebox.showwarning("Внимание", "Введите команду")
                return
            conf_path = f"proxychains_confs/session_{sid}.conf"
            full_cmd = f"proxychains -f {conf_path} {cmd}"
            self.log(f"Выполняем: {full_cmd}")

            def worker():
                try:
                    proc = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    for line in proc.stdout:
                        output_text.insert(tk.END, line)
                        output_text.see(tk.END)
                    proc.wait()
                    self.log(f"Команда завершена с кодом {proc.returncode}")
                except Exception as e:
                    self.log(f"Ошибка при выполнении команды: {e}")

            threading.Thread(target=worker, daemon=True).start()

        tk.Button(dialog, text="Запустить", command=run_cmd).pack()

    def show_graph(self):
        G = nx.DiGraph()
        for sid, s in self.sessions.items():
            root = f"Session {sid} ({s['ip']}:{s['port']})"
            G.add_node(root)
            for tun in s["tunnels"]:
                G.add_edge(root, tun)

        plt.figure(figsize=(10, 6))
        nx.draw_networkx(G, with_labels=True, node_size=2000, node_color="lightblue", arrowsize=20)
        plt.title("Граф туннелей")
        plt.show()

    def export_sessions(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return

        data = {}
        for sid, s in self.sessions.items():
            data[sid] = {
                "ip": s["ip"],
                "port": s["port"],
                "ping_interval": s["ping_interval"],
                "tunnels": s["tunnels"],
                "start_time": s["start_time"].isoformat(),
            }

        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=4)
            self.log(f"Сессии экспортированы в {path}")
        except Exception as e:
            messagebox.showerror("Ошибка экспорта", str(e))

    def import_sessions(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not path:
            return
        try:
            with open(path, "r") as f:
                data = json.load(f)
            for sid_str, sess in data.items():
                sid = int(sid_str)
                start_time = datetime.datetime.fromisoformat(sess["start_time"])
                self.create_session(sess["ip"], sess["port"], sess["ping_interval"], sid=sid, tunnels=sess["tunnels"])
                
            self.log(f"Сессии импортированы из {path}")
        except Exception as e:
            messagebox.showerror("Ошибка импорта", str(e))


if __name__ == "__main__":
    app = SessionManagerApp()
    app.mainloop()

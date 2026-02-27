# 🔧 Скрипт анализа DHCP-дампа (dhcp.pcapng) с использованием scapy
# 📦 Используемые библиотеки: scapy, matplotlib, seaborn, pandas
# 🗂️ Результат: CSV, JSON, графики

from scapy.all import *
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd  # 🛠️ ДОБАВЛЕН ИМПОРТ PANDAS
import json
from datetime import datetime

print("🚀 Запуск анализа DHCP-дампа...")

# 🧩 Этап 1: Загрузка данных через scapy
try:
    packets = rdpcap('dhcp.pcapng')
    print(f"✅ Загружено {len(packets)} пакетов")
except FileNotFoundError:
    print("❌ Файл dhcp.pcapng не найден в текущей папке!")
    exit()
except Exception as e:
    print(f"❌ Ошибка загрузки PCAP: {e}")
    exit()

# 🔎 Этап 2: Извлечение ключевых артефактов
dhcp_packets = []
dns_queries = []
suspicious_ips = set()
suspicious_domains = set()

for pkt in packets:
    # 🛠️ Ищем DHCP-пакеты
    if DHCP in pkt:
        dhcp_info = {
            'time': pkt.time,
            'src_ip': pkt[IP].src if IP in pkt else 'N/A',
            'dst_ip': pkt[IP].dst if IP in pkt else 'N/A',
            'dhcp_type': pkt[DHCP].options[0][1] if pkt[DHCP].options else 'N/A'
        }
        dhcp_packets.append(dhcp_info)

    # 🔎 Ищем DNS-запросы
    if DNS in pkt and pkt[DNS].qr == 0:  # DNS query
        query_name = pkt[DNSQR].qname.decode() if DNSQR in pkt else 'N/A'
        dns_query = {
            'time': pkt.time,
            'query': query_name,
            'src_ip': pkt[IP].src if IP in pkt else 'N/A'
        }
        dns_queries.append(dns_query)
        # 🚫 Эвристика: подозрительные домены
        if len(query_name) > 50 or any(char.isdigit() for char in query_name):
            suspicious_ips.add(pkt[IP].src)
            suspicious_domains.add(query_name)

print(f"✅ Найдено {len(dhcp_packets)} DHCP-пакетов и {len(dns_queries)} DNS-запросов.")

# 🏗️ Этап 3: Визуализация результатов
print("📊 Начало визуализации результатов...")

# 🗃️ Создаём DataFrame для DHCP
df_dhcp = pd.DataFrame(dhcp_packets)
df_dns = pd.DataFrame(dns_queries)

# 🔧 КОРРЕКЦИЯ: Преобразуем EDecimal в float перед конвертацией в datetime
def convert_to_timestamp(time_value):
    """Конвертирует EDecimal или другие типы в float timestamp"""
    if isinstance(time_value, (int, float)):
        return float(time_value)
    elif hasattr(time_value, 'real'):  # Для EDecimal
        return float(time_value.real)
    else:
        return float(time_value)

# Применяем конвертацию ко всем временным меткам
if not df_dhcp.empty:
    df_dhcp['timestamp'] = df_dhcp['time'].apply(convert_to_timestamp)
    df_dhcp['datetime'] = pd.to_datetime(df_dhcp['timestamp'], unit='s')

if not df_dns.empty:
    df_dns['timestamp'] = df_dns['time'].apply(convert_to_timestamp)
    df_dns['datetime'] = pd.to_datetime(df_dns['timestamp'], unit='s')

# 🗃️ Таблица 1: DHCP-пакеты с временем запуска
if not df_dhcp.empty:
    dhcp_table = df_dhcp[['datetime', 'src_ip', 'dst_ip', 'dhcp_type']].copy()
    dhcp_table.to_csv('dhcp_packets_table.csv', index=False, encoding='utf-8')
    print("🗃️ Таблица DHCP-пакетов сохранена как 'dhcp_packets_table.csv'")
else:
    print("⚠️ Нет данных DHCP для сохранения в таблицу.")

# 🗃️ Таблица 2: Подозрительные IP и домены
suspicious_data = []
for ip in suspicious_ips:
    for domain in suspicious_domains:
        suspicious_data.append({'Suspicious_IP': ip, 'Suspicious_Domain': domain})

suspicious_df = pd.DataFrame(suspicious_data)
if not suspicious_df.empty:
    suspicious_df.to_csv('suspicious_artifacts.csv', index=False, encoding='utf-8')
    print("🗃️ Список подозрительных IP и доменов сохранён как 'suspicious_artifacts.csv'")
else:
    print("⚠️ Подозрительных артефактов не обнаружено.")

# 💾 JSON: Полный дамп DHCP-пакетов
with open('dhcp_packets_full.json', 'w', encoding='utf-8') as f:
    # Предварительно конвертируем все временные метки в float
    json_dhcp_packets = []
    for packet in dhcp_packets:
        packet_copy = packet.copy()
        if isinstance(packet_copy['time'], (int, float)):
            packet_copy['timestamp'] = float(packet_copy['time'])
        elif hasattr(packet_copy['time'], 'real'):
            packet_copy['timestamp'] = float(packet_copy['time'].real)
        json_dhcp_packets.append(packet_copy)
    json.dump(json_dhcp_packets, f, indent=2, default=str)
print("💾 Полный дамп DHCP сохранён как 'dhcp_packets_full.json'")

# 📈 График 1: Количество DNS‑запросов по времени (часам)
plt.figure(figsize=(12, 6))
if not df_dns.empty:
    df_dns_hourly = df_dns.set_index('datetime').resample('H')['query'].count()
    df_dns_hourly.plot(kind='bar', color='skyblue')
    plt.title('📊 Количество DNS-запросов по часам')
    plt.ylabel('Число запросов')
    plt.xlabel('Время (часы)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('dns_requests_per_hour.png', dpi=300)
    print("🖼️ График DNS-запросов сохранён как 'dns_requests_per_hour.png'")
else:
    print("⚠️ Нет данных для построения графика DNS-запросов.")

# 📈 График 2: Распределение DHCP-типов
plt.figure(figsize=(8, 6))
if not df_dhcp.empty and 'dhcp_type' in df_dhcp.columns:
    dhcp_types = df_dhcp['dhcp_type'].value_counts()
    dhcp_types.plot(kind='pie', autopct='%1.1f%%')
    plt.title(' Распределение типов DHCP-сообщений')
    plt.ylabel('')
    plt.tight_layout()
    plt.savefig('dhcp_types_distribution.png', dpi=300)
    print("🖼️ График распределения DHCP-типов сохранён как 'dhcp_types_distribution.png'")
else:
    print("⚠ Нет данных для построения графика DHCP-типов.")

#  График 3: Топ-10 источников DNS‑запросов
plt.figure
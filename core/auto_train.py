import os
import pandas as pd
from core.data_collector import fetch_fresh_data
# Импорт функции обучения из train_brain
from core.train_brain import train_my_model

def full_auto_update():
    # 1. Тянет новые данные
    new_df = fetch_fresh_data()
    if new_df is None: return

    # 2. Загрузка старых данных
    csv_path = 'ai_data/cve_data.csv'
    if os.path.exists(csv_path):
        old_df = pd.read_csv(csv_path)
        # Объединяет, удаляя дубликаты по порту (новые данные важнее)
        final_df = pd.concat([new_df, old_df]).drop_duplicates(subset=['port'], keep='first')
    else:
        final_df = new_df

    # 3. Сохраняет обновленную базу
    final_df.to_csv(csv_path, index=False)
    print(f"[+] Database updated. Total ports: {len(final_df)}")

    # 4. Бью тряпкой модель, чтобы переучилась
    train_my_model()
    print("[+] AI Brain is now smarter and reloaded!")

if __name__ == "__main__":
    full_auto_update()


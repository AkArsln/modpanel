import sqlite3
import os


def check_database():
    db_path = os.path.join('instance', 'users.db')
    if not os.path.exists(db_path):
        print("Veritabanı dosyası bulunamadı!")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tabloları listele
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    print("\nVeritabanındaki tablolar:")
    for table in tables:
        print(f"- {table[0]}")

        # Her tablonun içeriğini göster
        cursor.execute(f"SELECT * FROM {table[0]}")
        rows = cursor.fetchall()
        print(f"  {len(rows)} kayıt bulundu")
        if rows:
            # İlk 5 kaydı göster
            for row in rows[:5]:
                print(f"  {row}")
            if len(rows) > 5:
                print(f"  ... ve {len(rows) - 5} kayıt daha")

    conn.close()


if __name__ == "__main__":
    check_database()
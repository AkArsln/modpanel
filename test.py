from bs4 import BeautifulSoup

with open("ModXPanel/mesaj_ekrani_U.txt", encoding="utf-8") as f:
    html = f.read()

soup = BeautifulSoup(html, "html.parser")
msgs = parse_momaily_ajx_message_history(soup)
print(f"Toplam mesaj: {len(msgs)}")
for m in msgs:
    print(m)
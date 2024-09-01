from bs4 import BeautifulSoup
import requests
import sqlite3
import json

def creating_db():
    """
    Создаёт базу данных Kaspersky с таблицами Vulnerabilities, Products, Vendors, Impacts
    """
    connect = sqlite3.connect("Kaspersky.sqlite")
    cursor = connect.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Impacts(
            impacts_id INTEGER PRIMARY KEY,
            impacts_name TEXT,
            vulnerability_id INTEGER,
            FOREIGN KEY (vulnerability_id) REFERENCES Vulnerabilities(vulnerability_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Vulnerabilities(
            vulnerability_id INTEGER PRIMARY KEY,
            vulnerability_name TEXT,
            product_id INTEGER,
            kaspersky_id INTEGER,
            FOREIGN KEY (product_id) REFERENCES Products(product_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Products(
            product_id INTEGER PRIMARY KEY,
            product_name TEXT,
            vendor_id INTEGER,
            FOREIGN KEY (vendor_id) REFERENCES Vendors(vendor_id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS Vendors(
            vendor_id INTEGER PRIMARY KEY,
            vendor_name TEXT
        )
        """
    )

    connect.commit()
    connect.close()

def get_product_id(connect, product_name):
    """
    Получает product_id из таблицы Products
    """
    cursor = connect.cursor()

    cursor.execute('''
    SELECT product_id FROM Products WHERE product_name = ?
    ''', (product_name,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def get_vendor_id(connect, vendor_name):
    """
    Получает vendor_id из таблицы Vendors
    """
    cursor = connect.cursor()

    cursor.execute('''
    SELECT vendor_id FROM Vendors WHERE vendor_name = ?
    ''', (vendor_name,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def get_vulnerability_id(connect, kaspesky_id):
    """
    Получает vulnerability_id из таблицы Vulnerabilities
    """
    cursor = connect.cursor()
    cursor.execute('''
    SELECT vulnerability_id FROM Vulnerabilities WHERE kaspesky_id = ?
    ''', (kaspesky_id,))

    result = cursor.fetchone()
    if result:
        return result[0]
    return None

def insert_impact(connect, impact_name, vulnerability_name):
    """
    Вставляет данные в таблицу Impacts
    """
    vulnerability_id = get_vulnerability_id(connect, vulnerability_name)
    cursor = connect.cursor()

    # Устанавливает vendor_id = 0, если он равен None
    if vendor_id is None:
        vendor_id = 0

    cursor.execute('''
    INSERT INTO Impacts (impact_name, vulnerability_id)
    VALUES (?, ?)
    ''', (impact_name, vulnerability_id))

    connect.commit()

def insert_vulnerability(connect, vulnerability_name, product_name, kaspersky_id):
    """
    Вставляет данные в таблицу Vulnerabilities
    """
    product_id = get_product_id(connect, product_name)
    cursor = connect.cursor()

    # Устанавливает product_id = 0, если он равен None
    if product_id is None:
        product_id = 0
    
    cursor.execute('''
    INSERT INTO Vulnerabilities (vulnerability_name, product_id, kaspersky_id)
    VALUES (?, ?, ?)
    ''', (vulnerability_name, product_id, kaspersky_id))

    connect.commit()

def insert_product(connect, product_name, vendor_name):
    """
    Вставляет данные в таблицу Products
    """
    vendor_id = get_vendor_id(connect, vendor_name)
    cursor = connect.cursor()

    # Устанавливает vendor_id = 0, если он равен None
    if vendor_id is None:
        vendor_id = 0

    cursor.execute('''
    INSERT INTO Products (product_name, vendor_id)
    VALUES (?, ?)
    ''', (product_name, vendor_id))

    connect.commit()

def insert_vendor(connect, vendor_name):
    """
    Вставляет данные в таблицу Vendors, если такого vendor_name еще нет
    """
    cursor = connect.cursor()

    # Проверяем, существует ли уже такой vendor_name
    cursor.execute('''
        SELECT vendor_id 
        FROM Vendors 
        WHERE vendor_name = ?
    ''', (vendor_name,))
    
    result = cursor.fetchone()

    if result is None:
        # Если vendor_name не найден, вставляем новый
        cursor.execute('''
            INSERT INTO Vendors (vendor_name)
            VALUES (?)
        ''', (vendor_name,))
        connect.commit()



def parse_vendors_pages(connect, base_url, start_page=1, end_page=15):
    """
    Парсит страницы Vendors
    """
    for page_num in range(start_page, end_page + 1):
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing vendors on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Извлекаем и вставляем названия в таблицу
        for container in containers:
            title_tag = container.find('div', class_='table__col_title')
            if title_tag and title_tag.a:
                vendor_name = title_tag.a.text.strip()
                insert_vendor(connect, vendor_name)

def parse_products_pages(connect, base_url, start_page=1, end_page=34):
    """
    Парсит страницы Products и вставляет данные в таблицу Products
    """
    for page_num in range(start_page, end_page + 1):
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing products on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Извлекаем и вставляем названия продуктов в таблицу
        for container in containers:
            product_tag = container.find('div', class_='table__col_title')
            vendor_tag = container.find_all('div', class_='table__col')[1]
            
            if product_tag and product_tag.a:
                product_name = product_tag.a.text.strip()
                if vendor_tag and vendor_tag.a:
                    vendor_name = vendor_tag.a.text.strip()
                    insert_product(connect, product_name, vendor_name)

def parse_vulnerabilities_pages(connect, base_url, start_page=1, end_page=108):
    """
    Парсит страницы уязвимостей и вставляет данные в таблицу Vulnerabilities
    """
    for page_num in range(start_page, end_page + 1):
        url = f"{base_url}?paged={page_num}"
        print(f"Parsing vulnerabilities on {url}...")

        # Загружаем HTML-контент страницы
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Находим все контейнеры с классом 'table__row'
        containers = soup.find_all('div', class_='table__row')

        # Извлекаем и вставляем данные об уязвимостях в таблицу
        for container in containers:
            # Извлечение идентификатора уязвимости
            kaspersky_id_tag = container.find('div', class_='table__col')
            kaspersky_id = kaspersky_id_tag.a.text.strip() if kaspersky_id_tag and kaspersky_id_tag.a else None
            
            # Извлечение названия уязвимости
            vulnerability_name_tag = container.find('div', class_='table__col_title')
            vulnerability_name = vulnerability_name_tag.a.text.strip() if vulnerability_name_tag and vulnerability_name_tag.a else None

            # Извлечение названия продукта
            product_tag = container.find_all('div', class_='table__col')[2]
            product_name = product_tag.a.text.strip() if product_tag and product_tag.a else None

            # Проверяем, что все данные есть перед вставкой
            if kaspersky_id and vulnerability_name and product_name:
                insert_vulnerability(connect, vulnerability_name, product_name, kaspersky_id)


def main():
    """
    Запускает скрипт
    """
    connect = sqlite3.connect('Kaspersky.sqlite', check_same_thread=False)
    creating_db()
    parse_vendors_pages(connect, "https://threats.kaspersky.com/en/vendor/")
    parse_products_pages(connect, "https://threats.kaspersky.com/en/product/")
    parse_vulnerabilities_pages(connect, "https://threats.kaspersky.com/en/vulnerability/")
    connect.close()

if __name__ == "__main__":
    main()

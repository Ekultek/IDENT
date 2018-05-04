import requests
from bs4 import BeautifulSoup


def send_request(url, ip_address, identifier="Blacklist Status"):
    data = requests.post(url, data={"ip": ip_address})
    html_content = data.content
    soup = BeautifulSoup(html_content, "html.parser")
    black_list_status = soup.find("td", text=identifier).find_next_sibling("td").text
    return ip_address, black_list_status

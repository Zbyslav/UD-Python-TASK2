import sys
import re
import requests
from bs4 import BeautifulSoup

def page(cve):
  # upload web-page and convert to beautiful_soup object
  url = 'https://www.cvedetails.com/cve/%s/' % (cve)
  r = requests.get(url)
  page = BeautifulSoup(r.text, "lxml")
  return page

def parse(page):
  # parse CVE info and return it with list
  res = []
  products = []
  res.append(page.title.string.split()[0])
  for td in page.find("table", id="cvssscorestable").findAll('td'):
    res.append(td.text.strip().split("\n")[0])
  for tr in page.find("table", id="vulnprodstable").findAll('tr'):
    product = [td.text.strip() for td in tr.findAll('td')]
    if product:
      products.append(product[0:5])
  res.append(products)
  return res

def output(list):
  #output to txt-file in human-readable form
  text1 = """              %s

CVSS SCORE: %s
Confidentiality Impact: %s
Integrity Impact: %s
Availability Impact: %s
Access Complexity: %s
Authentication: %s
Gained Access: %s
Vulnerability type(s): %s
CWE ID: %s

Products Affected:
  """
  text2 = """%s)
  Product Type: %s
  Vendor: %s
  Product: %s
  Version: %s
  """
  to_file = (text1 % tuple(list[0:10]))
  for product in list[-1]:
    to_file += (text2 % tuple(product))
  with open("cve/%s.txt" % list[0],"w") as file:
    file.write(to_file)
  print to_file

def main(argv):
  for cve in argv:
    output(parse(page(cve)))

if __name__ == "__main__":
  main(sys.argv[1:])

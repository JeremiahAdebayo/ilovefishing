import requests
import pandas as pd
import joblib as jb
import streamlit as st
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from bs4 import BeautifulSoup
from datetime import  datetime
from dateutil.parser import parse
from requests.exceptions import RequestException

st.title("🔍 Phishing URL Detector")
st.markdown("Enter a URL below to check if it's a phishing site.")
domain = st.text_input("🔗 URL:").lower()
button = st.button("verify")
API_KEY = st.secrets["API_KEY"]
no_error = True 
def get_value(result,key):
      try:
        return result.get(key) or "missing"  
      except:
        return "missing"

def script_count(bs):
        script_count = len(bs.find_all('script'))
        return script_count

def dash_dot_count(url):
        dot = url.count(".")
        dash = url.count("-")
        return dash,dot

def get_title(bs):
      try:
            title = bs.find("title").text
      except:
            title = "missing"
      return title
@st.cache_resource      
def load_model():
    return jb.load("phishing_detector_model.joblib")
      
if button:
    if not domain=="":
      with st.spinner("Analyzing...."):
      #WHOIS request
        clean_domain = domain.replace("https://www.", "").replace("http://www.", "").replace("https://", "").replace("http://", "").replace("www.","")
        #clean_domain = domain.replace("https://www.", "") if "www." in domain else domain.replace("https://", "") 
        url = f"https://api.apilayer.com/whois/query?domain={clean_domain}"
        payload = {}
        headers= {"apikey": API_KEY}
        try:
              response = requests.get(url, headers=headers, data = payload)
              response.raise_for_status()
              site_url = "https://" + clean_domain
              response_for_site = requests.get(site_url)
              response_for_site.raise_for_status()
              response_for_bs = response_for_site.text
              bs = BeautifulSoup(response_for_bs,"html.parser")
              results = response.json()
              result = results.get("result","missing")
        except RequestException as e:
              st.error(f"Failed to reach page : {e}")
              no_error = False

        #Feature engineering
        if no_error:
              no_of_script = script_count(bs)
              registrar = get_value(result,"registrar")
              whois_privacy = "yes" if registrar!="missing" else "no"
              title = get_title(bs)
              dash,dot = dash_dot_count(site_url)
      
              #Date parsing
              date = parse(get_value(result, "creation_date")).date()
              today = datetime.today().date()
              delta = (today - date).days
      
              features = pd.DataFrame({"URL":[url],
                                        "Registrar Name":[registrar],
                                        "WHOIS Privacy Enabled":[whois_privacy],
                                        "Page Title":[title],
                                        "Has Dash in Domain":[dash],
                                        "Number of Dots in Domain":[dot],
                                        "Number of <script> Tags":[no_of_script],
                                        "Domain Age(days)":[delta]
                                        })
                            
              model = load_model()
              verdict = model.predict(features)[0]
      
              if verdict==1:
                      st.error("Phishing site detected")
              else:
                      st.success("The site is safe")
      
      
      










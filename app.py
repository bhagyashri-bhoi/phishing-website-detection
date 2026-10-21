from flask import Flask, render_template, request
import joblib
import pandas as pd

app = Flask(__name__)

# Load trained Random Forest model
model = joblib.load("model.pkl")

feature_names = [
    'having_ip_address',
    'url_length',
    'shortining_service',
    'having_at_symbol',
    'double_slash_redirecting',
    'prefix_suffix',
    'having_sub_domain',
    'sslfinal_state',
    'domain_registration_length',
    'favicon',
    'port',
    'https_token',
    'request_url',
    'url_of_anchor',
    'links_in_tags',
    'sfh',
    'submitting_to_email',
    'abnormal_url',
    'redirect',
    'on_mouseover',
    'rightclick',
    'popupwindow',
    'iframe',
    'age_of_domain',
    'dnsrecord',
    'web_traffic',
    'page_rank',
    'google_index',
    'links_pointing_to_page',
    'statistical_report'
]


@app.route("/", methods=["GET", "POST"])
def home():

    prediction = None

    if request.method == "POST":

        values = [float(request.form[name]) for name in feature_names]

        input_data = pd.DataFrame([values], columns=feature_names)

        result = model.predict(input_data)[0]

        if result == -1:
            prediction = "Prediction: Phishing Website"
        else:
            prediction = "Prediction: Legitimate Website"

    return render_template("index.html", prediction=prediction)


if __name__ == "__main__":
    app.run(debug=True)
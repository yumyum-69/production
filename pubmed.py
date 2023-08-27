import json
from datetime import date, datetime
from pymed import PubMed
import pandas as pd
import re
import openai
import markdown
from google.cloud import translate_v2 as translate
import requests
from bs4 import BeautifulSoup
import re
import datetime


openai.api_key = "XXXXXXXXXXXXXXXX"
translate_client = translate.Client.from_service_account_json('XXXXXXXXXXXXXXXX.json')
pubmed = PubMed(tool="PubMedSearcher", email="XXXXXXXXXXXXXXXX")

def json_serial(obj):

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f'Type {obj} not serializable')


# PubMedでキーワード検索から論文を抽出
search_term = "Shoulder Injury Sports Rehabilitation"
results = pubmed.query(search_term, max_results=5)
articleList = []
articleInfo = []

for article in results:
    articleDict = article.toDict()
    articleList.append(articleDict)

for article in articleList:
    # この後の処理のため、アブストとPMIDを論文データから抜き出しておく
    str = json.dumps(article['abstract'])
    pubmedId = article['pubmed_id'].partition('\n')[0]

    articleInfo.append({u'pubmed_id': pubmedId,
                        u'title': article['title'],
                        u'keywords': article['keywords'],
                        u'journal': article['journal'],
                        u'abstract': str,
                        u'conclusions': article['conclusions'],
                        u'methods': article['methods'],
                        u'results': article['results'],
                        u'copyrights': article['copyrights'],
                        u'doi': article['doi'],
                        u'publication_date': article['publication_date'],
                        u'authors': article['authors']})

    # ChatGPTに投げるリクエストを整理
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system",
             "content": "You are an acclaimed sports commentator and blogger well known for your polite, gentlemanly language and quite understandable medical language. Please interpret the papers I present appropriately and explain them in an easy-to-understand manner. When writing your description, keep the following in mind:・Please limit the use of sports medicine terms to 5% or less.・In order to improve visibility, please write the summary in markdown format.- Use tables, lists, charts, graphs, etc. as appropriate.・Both the matching rate (copy-paste rate) and the citation rate should be 5% or less.・Please write with SEO in mind.At the end of the abstract, write a possible solution from the paper and your opinion on it in 100 characters or less. Please write both positive and pessimistic opinions."},
            {"role": "user",
             "content": str}
        ],
        max_tokens=1000,
        temperature=0.2
    )

    text = response.choices[0].message.content
    print(text)

    # マークダウン形式で書かれたレスポンステキストをHTMLに変換
    resource_message = markdown.markdown(text)

    print('-----------------')

    # HTMLごとGoogle Translation APIで翻訳
    result = translate_client.translate(resource_message, target_language="ja-JP", format_="html")
    print(result['translatedText'])

    # 論文データからCitation（引用情報）を生成
    url = "https://pubmed.ncbi.nlm.nih.gov/"+pubmedId
    res = requests.get(url)
    soup = BeautifulSoup(res.content, "html.parser")
    res = soup.find(attrs={'class': 'cit'}).text
    target = ';'
    idx = res.find(target)
    pagenation = res[idx + len(target):]
    pubDate = res[:idx]
    year = re.findall(r'\d+', pubDate)[0]
    month = re.findall(r'[a-zA-Z]+', pubDate)[0]
    day = re.findall(r'\d+', pubDate)[1]
    doi = article['doi'].splitlines()[0]
    dt = datetime.datetime.now()
    refDate = dt.strftime('%#d %b %Y')

    print('<blockquote class="wp-block-quote"><p>'+article['authors'][0]['lastname']+', '+article['authors'][0]['firstname']+' et al. "'+article['title']+'" <em>'+article['journal']+'</em>, '+pagenation+' '+day + ' ' + month + ' ' + year+', doi:'+doi+'</em></p><cite>pubMed, '+refDate+'</cite></blockquote>')
    print('-----------------')

# PandasのDataFrameを使って論文データをCSVに保存
articlesPD = pd.DataFrame.from_dict(articleInfo)
export_csv = articlesPD.to_csv(r'export_dataframe.csv', index=None, header=True)

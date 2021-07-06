import azure.functions as func
import fastapi
from fastapi.templating import Jinja2Templates

from .http_asgi import AsgiMiddleware
from .reports import gen_data
import xmltodict
import json

app = fastapi.FastAPI()
templates = Jinja2Templates(directory="./templates")


@app.get("/api/report/")
async def get_report_data(
    request: fastapi.Request,
    type: str,
    customer_id: str,
    edge_id: str,
    timeframe: str = "15m",
    format: str = "xml",
):
    """
    Args:
        type: 		    {report type} 		possible-compromised-hosts
        timeframe: 	    {report time frame}	options: 15m
        customer_id:	{customer bcrm ID}
        edge_id: 	    {customer edge ID}
        format:         {output format 'xml' or 'json'}

    """
    context = {
        "request": request,
        "type": type,
        "customer_id": customer_id,
        "edge_id": edge_id,
        "timeframe": timeframe,
    }
    # modern method of merging dicts (Python 3.9+ only)
    context = context | gen_data(report_type=type)
    if type == 'possible-compromised-hosts':
        data = templates.TemplateResponse(
            "possible-compromised-hosts.xml",
            context, media_type='application/xml')
    elif type == 'top-apps':
        data = templates.TemplateResponse(
            "top-apps.xml", context, media_type='application/xml')
    else:
        data = templates.TemplateResponse(
            "shampoo.xml", {"request": request, "id": id},
            media_type='application/xml')
    # return fastapi.Response(content=data, media_type="application/xml")
    if format == 'json':
        jsondata = xmltodict.parse(data.body.decode('utf-8'))
        data = fastapi.Response(content=json.dumps(
            jsondata, indent=2, sort_keys=False), media_type='text/json')
    return data


def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    return AsgiMiddleware(app).handle(req, context)

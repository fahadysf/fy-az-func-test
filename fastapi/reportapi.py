import azure.functions as func
from .http_asgi import AsgiMiddleware
import mimesis
import fastapi
from fastapi.templating import Jinja2Templates

app = fastapi.FastAPI()
templates = Jinja2Templates(directory="./templates")


@app.get("/api/user/{user_id}")
async def get_user(user_id: int):
    fake_user = mimesis.Person()
    return {
        "user_id": user_id,
        "username": fake_user.username(),
        "firstname": fake_user.first_name(),
        "lastname": fake_user.last_name(),
    }


@app.get("/api/report/")
def get_report_data(request: fastapi.Request, type: str, customer_id: str, edge_id: str, timeframe: str = "15m"):
    """
    Args:
        type: 		    {report type} 		possible-compromised-hosts
        timeframe: 	    {report time frame}	options: 15m
        customer_id:	{customer bcrm ID}
        edge_id: 	    {customer edge ID}

    """
    if type == 'possible-compromised-hosts':
        context = {
            "request": request,
            "type": type,
            "customer_id": customer_id,
            "edge_id": edge_id,
            "timeframe": timeframe,
        }

        data = templates.TemplateResponse(
            "possible-compromised-hosts.xml", context, media_type='application/xml')
    else:
        data = templates.TemplateResponse(
            "shampoo.xml", {"request": request, "id": id}, media_type='application/xml')
    # return fastapi.Response(content=data, media_type="application/xml")
    return data


def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    return AsgiMiddleware(app).handle(req, context)
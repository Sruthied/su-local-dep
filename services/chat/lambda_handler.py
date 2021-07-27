import json
import logging
import traceback
import boto3

from botocore.exceptions import ClientError
from bson import ObjectId
from datetime import datetime

from .settings import db_client

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handle_connect(user_id, connection_id):
    try:
        db_client["ChatConnections"].insert_one(
            {
                "userId": ObjectId(user_id),
                "connectionId": connection_id
            }
        )
        response = {
            "body": "Connection added successfully."
        }
        response_code = 200

    except Exception:
        logger.exception("Couldn't add connection")
        response = {
            "body": "Could'nt add connection."
        }
        response_code = 500

    return response, response_code


def handle_disconnect(connection_id):
    try:
        db_client["ChatConnections"].delete_one({"connectionId": connection_id})
        response = {
            "body": "Disconnected successfully."
        }
        response_code = 200

    except Exception:
        logger.exception("Could'nt disconnect connection")
        response = {
            "body": "Could'nt disconnect connection."
        }
        response_code = 500

    return response, response_code


def handle_message(sender_user_id, receiver_user_id, connection_id, event_body, apig_management_client):
    sender_connection = db_client["ChatConnections"].find_one(
        {
            "userId": ObjectId(sender_user_id),
            "connectionId": connection_id
        }
    )

    if not sender_connection:
        response = {
            "body": "Invalid sender connection id."
        }
        response_code = 400
        return response, response_code

    receiver_connection = db_client["ChatConnections"].find_one(
        {
            "userId": ObjectId(receiver_user_id)
        }
    )

    message = "{message}".format(message=event_body["message"]).encode("utf-8")
    logger.info("Message: %s", message)
    db_client.ChatMessages.insert_one(
        {
            "createdBy": ObjectId(sender_user_id),
            "createdFor": ObjectId(receiver_user_id),
            "createdOn": datetime.now(),
            "message": message,
            "read": False,
        }
    )
    response = {"body": "Message sent."}
    response_code = 200

    if receiver_connection:
        error = False
        try:
            connection_id = receiver_connection["connectionId"]
            send_response = apig_management_client.post_to_connection(
                Data=message, ConnectionId=connection_id
            )
            logger.info(
                "Posted message to connection %s, got response %s.",
                connection_id, send_response
            )

        except ClientError:
            error = True
            logger.exception("Couldn't post to connection %s.", connection_id)

        except apig_management_client.exceptions.GoneException:
            error = True
            logger.info("Connection %s is gone, removing.", connection_id)
            try:
                handle_disconnect(connection_id)
            except ClientError:
                logger.exception("Couldn't remove connection %s.", connection_id)
        
        except Exception:
            error = True
            logger.exception(traceback.format_exc())
        
        if error:
            response = {
                "body": "Something went wrong while sending message."
            }
            response_code = 500

    return response, response_code


def lambda_handler(event, context):

    try:
        headers = event.get("requestContext", {})
        query_params = event.get("queryStringParameters", {})
        body = json.loads(event["body"]) if event.get("body") else {}

        connection_id = headers.get("connectionId")
        route_key = body.get("routeKey") or headers.get("routeKey")
        sender_user_id = query_params.get("senderUserId") or body.get("senderUserId")

        if sender_user_id is None or route_key is None or connection_id is None:
            response = {"body": "Required parameters missing"}
            response_code = 400

        if route_key == "$connect":
            response, response_code = handle_connect(sender_user_id, connection_id)

        elif route_key == "$disconnect":
            response, response_code = handle_disconnect(connection_id)

        elif route_key == "sendmessage":
            receiver_user_id = body.get("receiverUserId")

            if not body:
                response = {"body": "Message body missing."}
                response_code = 400
            
            if receiver_user_id is None:
                response = {"body": "Receiver user id missing."}
                response_code = 400

            domain = headers.get("domainName")
            stage = headers.get("stage")
            if domain is None or stage is None:
                logger.warning(
                    "Bad endpoint in request"
                )
                response = {"body": "Bad endpoint in request."}
                response_code = 400
            else:
                apig_management_client = boto3.client(
                    "apigatewaymanagementapi", endpoint_url="https://{domain}/{stage}".format(domain=domain, stage=stage)
                )
                response, response_code = handle_message(
                    sender_user_id, receiver_user_id, connection_id, body, apig_management_client
                )
        else:
            response = {"body": "Unknown route."}
            response_code = 404

    
    except Exception:
        traceback.print_exc()
        response = {"body": "Something went wrong."}
        response_code = 500
    
    response["statusCode"] = response_code
    if int(response_code / 100) != 2:
        logger.info(event)

    return response

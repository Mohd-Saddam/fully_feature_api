# from sys import excepthook
# from urllib import response
# from django.http import Http404
# from rest_framework.views import exception_handler

# def custom_exception_handler(exc, context):

#     handlers={
#         'ValidationError':_handle_generic_error,
#         'Http404':_handle_generic_error,
#         'PermissionDenied':_handle_generic_error,
#         'NotAuthenticated':_handle_authentication_error
#     } 
#     response = exception_handler(exc,context)

#     if response is not None:

#         if "AuthUserAPIView" in str(context['view']) and exc.status_code==401:
#             response.status_code=200
#             response.data = {'is_logged_in':False,'status_code':200}

#             return response
#         response.data['status_code']=response.status_code
#     exception_class = exec.__class__.__name__

#     if exception_class in handlers:
#         return handlers[exception_class](excepthook,context,response)

# def _handle_authentication_error(exc,context,response):
#     response.data={
#         'error':'Please login to proceed',
#         'status_code':response.status_code
#     }
#     return response

# def _handle_generic_error():
#     return response
# from rest_framework.views import exception_handler
# from django.http import JsonResponse
 
# def get_response(message="", result={}, status=False, status_code=200):
#    return {
#        "message" : message,
#        "result" : result,
#        "status" : status,
#        "status_code" : status_code,
#    }
 
# def get_error_message(error_dict):
#    field = next(iter(error_dict))
#    response = error_dict[next(iter(error_dict))]
#    if isinstance(response, dict):
#        response = get_error_message(response)
#    elif isinstance(response, list):
#        response_message = response[0]
#        if isinstance(response_message, dict):
#            response = get_error_message(response_message)
#        else:
#            response = response[0]
#    return response
 
# def handle_exception(exc, context):
#    error_response = exception_handler(exc, context)
#    if error_response is not None:
#        error = error_response.data
 
#        if isinstance(error, list) and error:
#            if isinstance(error[0], dict):
#                error_response.data = get_response(
#                    message=get_error_message(error),
#                    status_code=error_response.status_code,
#                )
 
#            elif isinstance(error[0], str):
#                error_response.data = get_response(
#                    message=error[0],
#                    status_code=error_response.status_code
#                )
 
#        if isinstance(error, dict):
#            error_response.data = get_response(
#                message=get_error_message(error),
#                status_code=error_response.status_code
#            )
#    return error_response
 
# class ExceptionMiddleware(object):
#    def __init__(self, get_response):
#        self.get_response = get_response
 
#    def __call__(self, request):
 
#        response = self.get_response(request)
 
#        if response.status_code == 500:
#            response = get_response(
#                message="Internal server error, please try again later",
#                status_code=response.status_code
#            )
#            return JsonResponse(response, status=response['status_code'])
 
#        if response.status_code == 404 and "Page not found" in str(response.content):
#            response = get_response(
#                message="Page not found, invalid url",
#                status_code=response.status_code
#            )
#            return JsonResponse(response, status=response['status_code'])
 
#        return response
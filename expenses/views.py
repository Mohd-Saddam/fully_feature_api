from django.shortcuts import render
from rest_framework.generics import ListCreateAPIView, RetrieveUpdateDestroyAPIView
from rest_framework import permissions
from .permissions import IsOwner
# Create your views here.
from .serializers import ExpenseSerializer
from .models import Expense

class ExpenseListAPIView(ListCreateAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ExpenseSerializer
    queryset = Expense.objects.all()


    def perform_create(self,serializer):
        return serializer.save(owner=self.request.user)
    
    def get_queryset(self):
        
        return self.queryset.filter(owner=self.request.user)

class ExpenseDetailAPIView(RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,IsOwner,)
    serializer_class = ExpenseSerializer
    queryset = Expense.objects.all()
    lookup_field = 'id'


    def get_queryset(self):
        print("called")
        user = self.request.user.is_staff
        print("ui====================",user)
        return self.queryset.filter(owner=self.request.user)
    

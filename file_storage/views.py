from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from django.conf import settings
from django.core.files.storage import default_storage
from PIL import Image
from io import BytesIO
from drf_yasg.utils import swagger_auto_schema
from .serializers import FileUploadSerializer
from .models import UploadedFile
from .models import UploadedFile
from django.core.files.storage import default_storage
MAX_SIZE = 1048576  # 1MB in bytes


class FileUploadView(APIView):
    """
    Endpoint to upload a file. If the file exceeds 1MB, it will be compressed.
    """
    parser_classes = [MultiPartParser, FormParser]

    @swagger_auto_schema(
        operation_description="Upload a file. If the file exceeds 1MB, it will be compressed.",
        operation_summary="File Upload",
        request_body=FileUploadSerializer,
        responses={
            201: "File uploaded successfully",
            400: "Invalid file",
            500: "Error processing file"
        },
        tags=['Signup Flow']
    )
    def post(self, request, *args, **kwargs):
        """
        Handle file upload, compress if larger than 1MB, and return the URL.
        """
        serializer = FileUploadSerializer(data=request.data)

        if serializer.is_valid():
            uploaded_file = serializer.validated_data['file']
            file_url = None

            try:
                # If file size exceeds 1MB, compress the image
                if uploaded_file.size > MAX_SIZE:
                    image = Image.open(uploaded_file)
                    quality = 90  # Start with a good quality
                    compressed_image_io = BytesIO()

                    # Save the image to a BytesIO object with reduced quality
                    while True:
                        image.save(compressed_image_io, format='JPEG', quality=quality)
                        compressed_image_io.seek(0)
                        if compressed_image_io.tell() <= MAX_SIZE:
                            break
                        quality -= 5  # Reduce quality until under the size limit

                    # Save the compressed image back to the storage
                    compressed_image_io.seek(0)
                    file_name = default_storage.save(uploaded_file.name, compressed_image_io)
                    file_url = settings.MEDIA_URL + file_name
                else:
                    # If the image size is within the limit, save it directly
                    file_name = default_storage.save(uploaded_file.name, uploaded_file)
                    file_url = settings.MEDIA_URL + file_name

                # Save file to the database
                uploaded_file_instance = UploadedFile(file=file_name)
                uploaded_file_instance.save()

                # Build the full URL (base URL + media URL)
                # absolute_url = request.build_absolute_uri(file_url)
                absolute_url = request.build_absolute_uri(settings.MEDIA_URL + file_name)

                return Response({
                    "success": True,
                    "message": "File uploaded successfully",
                    "data": {"file_url": absolute_url}
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({
                    "success": False,
                    "message": f"Error while processing the file: {str(e)}",
                    "data": None
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "success": False,
            "message": "Invalid file",
            "data": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

class FileListView(generics.ListAPIView):
    """
    Endpoint to list all uploaded files.
    """
    queryset = UploadedFile.objects.all()
    serializer_class = FileUploadSerializer

    @swagger_auto_schema(
        operation_description="List all uploaded files with their URLs.",
        operation_summary="List Uploaded Files",
        responses={
            200: "Files fetched successfully",
            400: "Bad request"
        },
        tags=['File Management'] 
    )
    def get(self, request, *args, **kwargs):
        """
        List all files with their URLs.
        """
        files = self.get_queryset()
        serialized_files = self.get_serializer(files, many=True)
        return Response({
            "success": True,
            "message": "Files fetched successfully",
            "data": serialized_files.data
        }, status=status.HTTP_200_OK)
class UserView(APIView):
    """
    Endpoint to manage user information.
    """

    @swagger_auto_schema(
        operation_description="Get user details",
        operation_summary="Get User Details",
        tags=['User Management']  # Group this view under 'User Management'
    )
    def get(self, request, *args, **kwargs):
        """
        Get user details.
        """
        # Your user fetching logic here...
        return Response({"success": True, "message": "User details fetched successfully"}, status=status.HTTP_200_OK)
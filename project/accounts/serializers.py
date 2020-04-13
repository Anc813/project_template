from rest_framework import serializers




class LoginSerializer(serializers.Serializer):  # noqa: E501 pylint: disable=abstract-method

    email = serializers.EmailField()
    password = serializers.CharField(min_length=8)
    class Meta:
        fields = (
            'email',
            'password',

        )

# SecureDB Client Side Program Reference

## `SecureDB.set_api_url(api_url)`

Sets the URL of the SecureDB API endpoint. Typically, the value of `api_url` is `http://<db-server-ip-address>:4999/api/database` (substitute `<db-server-ip-address>` with the IP address of the server where SecureDB is running).

### Parameters

- `api_url`: The full, absolute URL of the SecureDB API endpoint.

## `SecureDB.set_api_key(api_key)`

Sets the API key to authenticate requests sent to the SecureDB API endpoint.

### Parameters

- `api_key`: The API key to authenticate requests sent to the SecureDB API endpoint. Specify the API key as a string of 32 hex digits.

## `SecureDB.create(model, object_)`

Sends a POST request to the SecureDB API endpoint to create an object. This method will return the created object if you need to access fields that are only available after committing (such as the primary key).

### Parameters

- `model`: The model you want to create, specified as a string.
- `object_`: The object that you want to commit to SecureDB.

## `SecureDB.retrieve(model, filter_)`

Sends a GET request to the SecureDB API endpoint to retrieve the list of filtered object(s). This method will return a list of filtered, deserialized SQLAlchemy object(s).

### Parameters

- `model`: The model you want to query, specified as a string.
- `filter_`: The filter to apply on the query.

## `SecureDB.update(model, filter_, values)`

Sends a PATCH request to the SecureDB API endpoint to update the first filtered object with the specified values.

### Parameters

- `model`: The model you want to query, specified as a string.
- `filter_`: The filter to apply on the query.
- `values`: The fields you want to update, specified as a dictionary (the key(s) are the name of the field(s) you want to update, and the value(s) are the new value(s) to be assigned to the corresponding field(s)).

## `SecureDB.delete(model, filter_)`

Sends a DELETE request to the SecureDB API endpoint to delete the first filtered object.

### Parameters

- `model`: The model you want to query, specified as a string.
- `filter_`: The filter to apply on the query.

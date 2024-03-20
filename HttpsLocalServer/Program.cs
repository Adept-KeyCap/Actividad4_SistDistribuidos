using System;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using Newtonsoft.Json;
using System.Linq;

string ip = "127.0.0.1";
int port = 1234;
List<User> usersList = new List<User>();


usersList.Add((new User() { password = "123456", username = "manolo" }));


var listener = new HttpListener();
listener.Prefixes.Add($"http://{ip}:{port}/");
listener.Start();

Console.WriteLine($"Servidor HTTP en ejecución en http://{ip}:{port}/");

while (true)
{
    var context = await listener.GetContextAsync();
    HandleRequest(context);
}

async void HandleRequest(HttpListenerContext context)
{
    var request = context.Request;
    var response = context.Response;

    Console.WriteLine($"Petición recibida: {request.HttpMethod} {request.RawUrl}");

    //endpoint Login
    if (request.HttpMethod == "POST" && request.RawUrl == "/api/auth/login")
    {
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        AuthData authData = JsonConvert.DeserializeObject<AuthData>(requestBody);

        //VALIDACIONES
        if (string.IsNullOrEmpty(authData?.username))
        {
            SendResponse("{\"msg\": \"debe enviar el campo username en la petición\",\"field\": \"username\"}", 400, response);
        }
        else if (string.IsNullOrEmpty(authData.password))
        {
            SendResponse("{\"msg\": \"debe enviar el campo password en la petición\",\"field\": \"password\"}", 400, response);

        }
        else if (!usersList.Any(u => u.username == authData.username))
        {
            SendResponse("{\"msg\": \"usuario o contraseña no son correctos - username\"}", 400, response);
        }
        else//Validaciones superadas
        {
            var usuarioDB = usersList.First(u => u.username == authData.username);
            if (usuarioDB.password != authData.password)
            {
                SendResponse("{\"msg\": \"usuario o contraseña no son correctos - password\"}", 400, response);
            }
            else
            {
                AuthResponse authResponse = new AuthResponse(usuarioDB);
                string contentResponse = JsonConvert.SerializeObject(authResponse);
                SendResponse(contentResponse, 200, response);

            }
        }
        return;
    }

    //endpoint Registro
    if (request.HttpMethod == "POST" && request.RawUrl == "/api/usuarios")
    {
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        User usuario = JsonConvert.DeserializeObject<User>(requestBody);

        if (string.IsNullOrEmpty(usuario?.username))
        {
            SendResponse("{\"msg\": \"debe enviar el campo username en la petición\",\"field\": \"username\"}", 400, response);
        }
        else if (string.IsNullOrEmpty(usuario.password))
        {
            SendResponse("{\"msg\": \"debe enviar el campo password en la petición\",\"field\": \"password\"}", 400, response);

        }
        else if (usersList.Any(u => u.username == usuario.username))
        {
            SendResponse("{\"msg\": \"El usuario ya existe\"}", 400, response);
        }
        else
        {
            usersList.Add(usuario);
            var usuarioDB = usersList.First(u => u.username == usuario.username);
            AuthResponse authResponse = new AuthResponse(usuarioDB);
            string contentResponse = JsonConvert.SerializeObject(authResponse.token);

            SendResponse("{\"msg\": \"El usuario ha sido generado\"}", 201, response);
        }
        return;
    }

    //endpoint Listar usuarios
    if (request.HttpMethod == "GET" && request.RawUrl == "/api/usuarios")
    {
        string token = request.Headers["x-token"];
        
        if (string.IsNullOrEmpty(token))
        {
            SendResponse("{\"msg\": \"No hay token en la peticion\"}", 401, response);
        }
        else if(!EsGUID(token))
        {
            SendResponse("{\"msg\": \"El token no es valido\"}", 401, response);
        }
        else
        {
            string json = JsonConvert.SerializeObject(new UserList(usersList));
            SendResponse(json, 200, response);
        }
        return;
    }
    //endpoint Actualizar los usuarios
    if (request.HttpMethod == "PATCH" && request.RawUrl.StartsWith("/api/usuarios"))
    {
        string token = request.Headers["x-token"];
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        User usuario = JsonConvert.DeserializeObject<User>(requestBody);

        if (string.IsNullOrEmpty(token))
        {
            SendResponse("{\"msg\": \"No hay token en la peticion\"}", 401, response);
            return;
        }
        else if (!EsGUID(token))
        {
            SendResponse("{\"msg\": \"El token no es valido\"}", 401, response);
            return;
        }
        else if (!usersList.Any(u => u.username == usuario.username))
        {
            SendResponse("{\"msg\": \"No se encontro el usuario\"}", 404, response);
            return;
        }
        else
        {
            var usuarioDB = usersList.First(u => u.username == usuario.username);
            usuarioDB.data.score = usuario.data.score;
            usersList.Find(usuario1 => usuario1.username == usuario.username).data.score = usuarioDB.data.score;

            SendResponse("{\"msg\": \"El usuario ha sido actualizado\" }", 200, response);
            return;
        }
    }
    SendResponse("{\"msg\": \"No se encontro nada\"}", 404, response);
}


async void SendResponse(string content, int statusCode, HttpListenerResponse response)
{
    int contentLength = System.Text.Encoding.UTF8.GetByteCount(content);

    response.ContentLength64 = contentLength;
    response.ContentType = "application/json";
    response.StatusCode = statusCode;

    var output = response.OutputStream;
    var buffer = System.Text.Encoding.UTF8.GetBytes(content);
    await output.WriteAsync(buffer, 0, buffer.Length);

    output.Close();
}

bool EsGUID(string str)
{
    Guid resultado;
    return Guid.TryParse(str, out resultado);
}


class AuthResponse
{
    public User usuario { get; set; }
    public string token { get; set; }
    public AuthResponse(User usuarioDB)
    {
        usuario = usuarioDB;
        token = Guid.NewGuid().ToString();
    }
}

class AuthData
{
    public string username { get; set; }
    public string password { get; set; }
}

class User
{
    public string username { get; set; }
    public string password { get; set; }
    public bool estado { get; set; }
    public UserData data { get; set; }

    public User()
    {
        data = new UserData();
        estado = true;
    }
}

class UserList
{
    public List<User> usuarios { get; set; }
    public UserList(List<User> usuarios)
    {
        this.usuarios = usuarios;
    }
}

class UserData
{
    public int score { get; set; }
}
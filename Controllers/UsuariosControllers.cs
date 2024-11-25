using Exo.WebApi.Models;
using Exo.WebApi.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
namespace Exo.WebApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;
        public UsuariosController(UsuarioRepository usuarioRepository)
        {
            _usuarioRepository = usuarioRepository;
        }
        //get
        [HttpGet]
        public IActionResult Listar()
        {
            return Ok(_usuarioRepository.Listar());
        }
        // post
        // [HttpPost]
        // public IActionResult Cadastrar(Usuario usuario)
        // {
        //     _usuarioRepository.Cadastrar(usuario);
        //     return StatusCode(201);
        // }
// Novo código POST Login
        public IActionResult Post(Usuario usuario)
        {
            Usuario usuarioBuscado = _usuarioRepository.Login(usuario.Email, usuario.Senha);
            if (usuarioBuscado == null)
            {
                return NotFound("E-mail ou senha inválidos!");
            }
        // Se o usuário for encontrado criar token
        // Define os dados Token
        var claims = new[]
        {
            // Armazena email
            new Claim(JwtRegisteredClaimNames.Email, usuarioBuscado.Email),
            // Armazena ID
            new Claim(JwtRegisteredClaimNames.Jti, usuarioBuscado.Id.ToString()),};
        // Define a chave de acesso
        var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chaveautenticacao"));
        // Define as credenciais 
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        // Gera o token
        var token = new JwtSecurityToken(
        issuer: "exoapi.webapi", // Emissor do token
        audience: "exoapi.webapi", // Destinatário do token
        claims: claims, // Dados definidos acima
        expires: DateTime.Now.AddMinutes(30), // Tempo de expiração
        signingCredentials: creds // Credenciais do token
        );
        return Ok(
            new { token = new JwtSecurityTokenHandler().WriteToken(token) }
        );
        }   
// Fim código POST para auxiliar o Login

        // get ID
        [HttpGet("{id}")] // Busca o ID.
        public IActionResult BuscarPorId(int id)
        {
            Usuario usuario = _usuarioRepository.BuscaPorId(id);
            if (usuario == null)
            {
                return NotFound();
            }
            return Ok(usuario);
        }
        // put ID
        // Atualizar
        [Authorize]
        [HttpPut("{id}")]
        public IActionResult Atualizar(int id, Usuario usuario)
        {
            _usuarioRepository.Atualizar(id, usuario);
            return StatusCode(204);
        }
        // delete ID
        [Authorize]
        [HttpDelete("{id}")]
        public IActionResult Deletar(int id)
        {
            try
            {
                _usuarioRepository.Deletar(id);
                return StatusCode(204);
            }
            catch (Exception)
            {
                return BadRequest();
            }
        }
    }
}

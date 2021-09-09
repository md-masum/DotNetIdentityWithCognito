namespace DotNetIdentityWithCognito.Interface
{
    public interface ICurrentUserService
    {
        string UserId { get; }
        string UserName { get; }
        string Email { get; }
    }
}
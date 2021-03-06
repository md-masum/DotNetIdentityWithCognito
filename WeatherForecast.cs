using System;

namespace DotNetIdentityWithCognito
{
    public class WeatherForecast
    {
        public DateTime Date { get; set; }

        public int TemperatureC { get; set; }

        public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

        public string Summary { get; set; }

        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}

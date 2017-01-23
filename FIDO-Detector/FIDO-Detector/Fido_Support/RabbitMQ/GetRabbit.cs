using System;
using System.Text;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using RabbitMQ.Client.MessagePatterns;

namespace FIDO_Detector.Fido_Support.RabbitMQ
{
  class GetRabbit
  {
    public void Get(string sQueue, string hostname)
    {
      var connectionFactory = new ConnectionFactory { HostName = hostname };

      using (var connection = connectionFactory.CreateConnection())
      {
        using (var model = connection.CreateModel())
        {
          var subscription = new Subscription(model, sQueue, false);
          while (true)
          {
            BasicDeliverEventArgs basicDeliveryEventArgs = subscription.Next();
            var messageContent = Encoding.UTF8.GetString(basicDeliveryEventArgs.Body);
            Console.WriteLine(messageContent);
            subscription.Ack(basicDeliveryEventArgs);
          }
        }
      }
    }
  }
}

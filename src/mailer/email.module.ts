import { Module } from '@nestjs/common';
import { MailerConfigService } from '../config/mailer.config.js';
import { MailerModule } from '@nestjs-modules/mailer';
import { EmailService } from './services/email.service.js';

@Module({
  imports: [
    MailerModule.forRootAsync({
      useClass: MailerConfigService,
    }),
  ],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}

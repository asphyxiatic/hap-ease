import { MigrationInterface, QueryRunner } from "typeorm";

export class AddTokensAndUsersTables1694073340380 implements MigrationInterface {
    name = 'AddTokensAndUsersTables1694073340380'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "tokens" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "value" character varying NOT NULL, "user_id" uuid NOT NULL, CONSTRAINT "PK_3001e89ada36263dabf1fb6210a" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "users" ("created_at" TIMESTAMP NOT NULL DEFAULT now(), "update_at" TIMESTAMP NOT NULL DEFAULT now(), "id" uuid NOT NULL DEFAULT uuid_generate_v4(), "email" character varying NOT NULL, "phone" character varying, "nickname" character varying NOT NULL, "password" character varying NOT NULL, "active" character varying NOT NULL DEFAULT false, "recovery_token" character varying, "confirmation_token" character varying, CONSTRAINT "PK_a3ffb1c0c8416b9fc6f907b7433" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "tokens" ADD CONSTRAINT "FK_8769073e38c365f315426554ca5" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "tokens" DROP CONSTRAINT "FK_8769073e38c365f315426554ca5"`);
        await queryRunner.query(`DROP TABLE "users"`);
        await queryRunner.query(`DROP TABLE "tokens"`);
    }

}

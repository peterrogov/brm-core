import { Entity, PrimaryGeneratedColumn, Column, Index, Generated } from 'typeorm';

@Entity()
export class DataEncryptionKey {
    @PrimaryGeneratedColumn()
    id: number;

    @Column({ type: "timestamp", default: new Date() })
    @Index()
    createdAt: Date;

    @Column()
    @Index()
    enabled: boolean;

    @Column("bytea")
    keyEnvelope: Buffer;
}

import { Column, Entity, Generated, Index, PrimaryGeneratedColumn } from 'typeorm';

@Entity()
@Index(["documentId", "isCurrent"])
export class EncryptedDocument {
    @PrimaryGeneratedColumn()
    id: number;

    @Column()
    @Generated("uuid")
    @Index()
    documentId: string;

    @Column()
    @Index()
    isCurrent: boolean;

    @Column({ default: null, nullable: true })
    @Index()
    mergedInto: string;

    @Column()
    @Index()
    type: string;

    @Column({ type: "timestamp" })
    @Index()
    createdAt: Date;

    @Column({ type: "integer" })
    @Index()
    dekId: number;

    @Column("bytea")
    payload: Buffer;
}

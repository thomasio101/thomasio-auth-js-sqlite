import { Database, open } from 'sqlite';
import * as common from 'thomasio-auth-js-common/lib/server';

export type UserFetcher<I, P> = (
	username: string,
	dbPromise: Promise<Database>,
) => Promise<{ storedPassword: P; identity: I } | null>;

export type UserCreator<E, I, P> = (
	username: string,
	processedPasswordPromise: Promise<P>,
	dbPromise: Promise<Database>,
) => Promise<{ success: true; identity: I } | { success: false; error: E }>;

export type SessionFetcher<I, T> = (
	id: string,
	dbPromise: Promise<Database>,
) => Promise<{ storedToken: T; identity: I } | null>;

export type SessionCreator<I> = (identity: I, dbPromise: Promise<Database>) => Promise<common.ISession<I>>;

export class SqliteDatabaseInterface<E, I, P, T> implements common.IDatabaseInterface<E, I> {
	private dbPromise: Promise<Database>;
	private userFetcher: UserFetcher<I, P>;
	private passwordVerifier: common.Verifier<P>;
	private passwordProcessor: common.Processor<P>;
	private sessionCreator: SessionCreator<I>;
	private sessionFetcher: SessionFetcher<I, T>;
	private tokenVerifier: common.Verifier<T>;
	/* tslint:disable-next-line */
	private _userCreator: UserCreator<E, I, P>;

	// TODO: Replace identity in userFetcher with a function which fetches the identity.
	constructor(
		dbFileName: string,
		userFetcher: UserFetcher<I, P>,
		passwordVerifier: common.Verifier<P>,
		passwordProcessor: common.Processor<P>,
		sessionCreator: SessionCreator<I>,
		sessionFetcher: SessionFetcher<I, T>,
		tokenVerifier: common.Verifier<T>,
		userCreator: UserCreator<E, I, P>,
	) {
		this.dbPromise = open(dbFileName);
		this.userFetcher = userFetcher;
		this.passwordVerifier = passwordVerifier;
		this.passwordProcessor = passwordProcessor;
		this.sessionCreator = sessionCreator;
		this.sessionFetcher = sessionFetcher;
		this.tokenVerifier = tokenVerifier;
		this._userCreator = userCreator;
	}

	public async userAuthenticator(
		username: string,
		password: string,
	): Promise<{ valid: true; session: common.ISession<I> } | { valid: false }> {
		const userFetcherResult = await this.userFetcher(username, this.dbPromise);

		if (userFetcherResult !== null) {
			if (await this.passwordVerifier(userFetcherResult.storedPassword, password)) {
				return {
					session: await this.sessionCreator(userFetcherResult.identity, this.dbPromise),
					valid: true,
				};
			} else {
				return {
					valid: false,
				};
			}
		} else {
			return {
				valid: false,
			};
		}
	}

	public async sessionAuthenticator(session: common.ISession<I>) {
		const sessionFetcherResult = await this.sessionFetcher(session.id, this.dbPromise);

		if (sessionFetcherResult !== null) {
			session.identity = sessionFetcherResult.identity;

			return await this.tokenVerifier(sessionFetcherResult.storedToken, session.token);
		} else {
			return false;
		}
	}

	public userCreator(
		username: string,
		password: string,
	): Promise<{ success: true; identity: I } | { success: false; error: E }> {
		return this._userCreator(username, this.passwordProcessor(password), this.dbPromise);
	}
}

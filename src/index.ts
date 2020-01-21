import { Database, open } from 'sqlite';
import { IDatabaseInterface, ISession, Verifier } from 'thomasio-auth-js-common/lib/server';

export type UserFetcher<I, P> = (
	username: string,
	dbPromise: Promise<Database>,
) => Promise<{ storedPassword: P; identity: I } | null>;

export type UserCreator<E, I, P> = (
	username: string,
	processedPasswordPromise: Promise<P>,
) => Promise<{ success: true; identity: I } | { success: false; error: E }>;

export type SessionFetcher<I, T> = (
	id: string,
	dbPromise: Promise<Database>,
) => Promise<{ storedToken: T; identity: I } | null>;

export type SessionCreator<I> = (identity: I, dbPromise: Promise<Database>) => Promise<ISession<I>>;

export class SqliteDatabaseInterface<I, P, T> implements IDatabaseInterface<I> {
	private dbPromise: Promise<Database>;
	private userFetcher: UserFetcher<I, P>;
	private passwordVerifier: Verifier<P>;
	private sessionCreator: SessionCreator<I>;
	private sessionFetcher: SessionFetcher<I, T>;
	private tokenVerifier: Verifier<T>;

	// TODO: Replace identity in userFetcher with a function which fetches the identity.
	constructor(
		dbFileName: string,
		userFetcher: UserFetcher<I, P>,
		passwordVerifier: Verifier<P>,
		sessionCreator: SessionCreator<I>,
		sessionFetcher: SessionFetcher<I, T>,
		tokenVerifier: Verifier<T>,
	) {
		this.dbPromise = open(dbFileName);
		this.userFetcher = userFetcher;
		this.passwordVerifier = passwordVerifier;
		this.sessionCreator = sessionCreator;
		this.sessionFetcher = sessionFetcher;
		this.tokenVerifier = tokenVerifier;
	}

	public async userAuthenticator(
		username: string,
		password: string,
	): Promise<{ valid: true; session: ISession<I> } | { valid: false }> {
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

	public async sessionAuthenticator(session: ISession<I>) {
		const sessionFetcherResult = await this.sessionFetcher(session.id, this.dbPromise);

		if (sessionFetcherResult !== null) {
			session.identity = sessionFetcherResult.identity;

			return await this.tokenVerifier(sessionFetcherResult.storedToken, session.token);
		} else {
			return false;
		}
	}
}

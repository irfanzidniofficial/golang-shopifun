package entity

type UserResult struct {
	Id    string `db:"id"`
	Role  string `db:"role"`
	Name  string `db:"name"`
	Email string `db:"email"`
	Pass  string `db:"password"`
}

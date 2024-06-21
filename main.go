package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"sort"
	"time"
)

var jwtKey = []byte("my_secret_key_is_LOVE_forever")

type Claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	Group string `json:"group"`

	jwt.StandardClaims
}

type User struct {
	ID      primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name    string             `json:"name" bson:"name"`
	Surname string             `json:"surname" bson:"surname"`
	Email   string             `json:"email" bson:"email"`
	Pass    string             `json:"pass" bson:"pass"`
	Group   string             `json:"group" bson:"group"`
	Role    string             `json:"role" bson:"role"`
}

type GroupToGet struct {
	Groups string `json:"name" bson:"name"`
}

type Lesson struct {
	ID         primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Groups     []Group            `json:"groups" bson:"groups"`
	StartTime  int                `json:"startTime" bson:"startTime"`
	DayOfWeek  int                `json:"day_of_week" bson:"day_of_week"`
	TypeLesson string             `json:"typeLesson" bson:"typeLesson"`
	Subject    Subject            `json:"subject" bson:"subject"`
	Room       Room               `json:"room" bson:"room"`
	Teacher    User               `json:"teacher" bson:"teacher"`
}

type Response struct {
	Token string `json:"token"`
}

type Group struct {
	ID     primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name   string             `json:"name" bson:"name"`
	Course int                `json:"course" bson:"course"`
}

type Subject struct {
	ID   primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name string             `json:"name" bson:"name"`
}

type Room struct {
	ID   primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name string             `json:"name" bson:"name"`
}

// Структура для запроса смены пароля
type ChangePasswordRequest struct {
	OldPassword string `json:"oldPassword"`
	NewPassword string `json:"newPassword"`
}

func main() {

	// Подключение к MongoDB
	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(context.Background())

	// Создание маршрутизатора
	router := httprouter.New()

	router.POST("/register", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		registerUser(w, r, client)
	})

	router.POST("/add/group", isAuthorized(addGroup(client)))
	router.POST("/add/subject", isAuthorized(addSubject(client)))
	router.POST("/add/room", isAuthorized(addRoom(client)))
	router.POST("/add/lesson", isAuthorized(addLesson(client)))

	// Обработчик POST запросов для входа пользователя
	router.POST("/account/login", handleLogin(client))

	// Get requests
	router.GET("/lesson/all", getAllLessons(client))
	router.GET("/get/user", isAuthorized(getUser(client)))
	router.GET("/get/subjects", isAuthorized(getAllSubjects(client)))
	router.GET("/get/rooms", isAuthorized(getAllRooms(client)))
	router.GET("/get/teachers", isAuthorized(getAllTeachers(client)))
	router.POST("/get/lessons", isAuthorized(getLessons(client)))

	router.DELETE("/lesson/delete/:id", isAuthorized(deleteLesson(client)))
	router.PUT("/lesson/update/:id", isAuthorized(updateLesson(client)))

	router.PUT("/update/password", isAuthorized(changePassword(client)))

	// Запуск HTTP сервера
	log.Println("Server started at :8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}

// Функция для смены пароля
func changePassword(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Проверка авторизации
		fmt.Println("Changing password")
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("Changing password1")

		// Проверка токена
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		fmt.Println("Changing password2")
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Println("Changing password3")

		// Получение данных из запроса
		var req ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		fmt.Println("Changing password4")
		fmt.Println(r.Body)
		// Поиск пользователя в базе данных
		usersCollection := client.Database("INAI").Collection("users")
		var user User
		err = usersCollection.FindOne(context.Background(), bson.M{"email": claims.Email}).Decode(&user)
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		fmt.Println("Changing password5")
		fmt.Println(user)
		fmt.Println(req)
		// Проверка старого пароля
		if err := bcrypt.CompareHashAndPassword([]byte(user.Pass), []byte(req.OldPassword)); err != nil {
			http.Error(w, "Invalid old password", http.StatusUnauthorized)
			return
		}
		fmt.Println("Changing password6")

		// Хеширование нового пароля
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}
		fmt.Println("Changing password7")

		// Обновление пароля в базе данных
		_, err = usersCollection.UpdateOne(
			context.Background(),
			bson.M{"email": claims.Email},
			bson.M{"$set": bson.M{"pass": string(hashedPassword)}},
		)
		fmt.Println("Changing password8")
		if err != nil {
			http.Error(w, "Error updating password", http.StatusInternalServerError)
			return
		}

		fmt.Println("Changing password9")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "Password updated successfully"})
	}
}

// Получение пользователя
func getUser(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get user")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized2", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized3", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" && claims.Role != "student" && claims.Role != "teacher" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if !ok {
			http.Error(w, "Unauthorized4", http.StatusUnauthorized)
			return
		}

		// Поиск пользователя в базе данных по email
		usersCollection := client.Database("INAI").Collection("users")
		var user User
		err = usersCollection.FindOne(context.Background(), bson.M{"email": claims.Email}).Decode(&user)
		user.Role = claims.Role
		if err != nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		fmt.Println(user)
		user.Pass = ""
		// Возврат данных о пользователе в формате JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(user); err != nil {
			http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
			return
		}
	}
}

// Получение уроков
func getLessons(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Println("Get lessons")

		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var requestBody struct {
			Day string `json:"day"`
		}

		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println(requestBody)
		day := 1
		if requestBody.Day == "monday" {
			day = 1
		} else if requestBody.Day == "tuesday" {
			day = 2
		} else if requestBody.Day == "wednesday" {
			day = 3
		} else if requestBody.Day == "thursday" {
			day = 4
		} else if requestBody.Day == "friday" {
			day = 5
		} else if requestBody.Day == "saturday" {
			day = 6
		}
		ctx := context.Background()
		lessonCollection := client.Database("INAI").Collection("lessons")

		var dayRange bson.M
		dayRange = bson.M{"$gte": 1, "$lte": 7}
		fmt.Println(requestBody.Day, dayRange)

		cursor, err := lessonCollection.Find(ctx, bson.M{"day_of_week": dayRange}, options.Find().SetSort(bson.D{
			{"day_of_week", 1},
			{"start_time", 1},
		}))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		var lessons []Lesson
		for cursor.Next(ctx) {
			var lesson Lesson
			if err := cursor.Decode(&lesson); err != nil {
				http.Error(w, "Failed to decode lesson", http.StatusInternalServerError)
				log.Println("Failed to decode lesson:", err)
				return
			}
			if lesson.DayOfWeek == day {
				if "teacher" == claims.Role {
					if lesson.Teacher.Email == claims.Email {
						lessons = append(lessons, lesson)
					}
				} else {
					for _, group := range lesson.Groups {

						if group.Name == claims.Group {
							lessons = append(lessons, lesson)
							break
						}
					}
				}
			}
		}

		// Сортировка уроков по StartTime
		sort.Slice(lessons, func(i, j int) bool {
			return lessons[i].StartTime < lessons[j].StartTime
		})

		if err := cursor.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(lessons); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

/*
func getLessons(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Println("Get lessons")
		// Проверка авторизации
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var requestBody struct {
			Group string `json:"group"`
			Week  int    `json:"week"`
		}
		// Декодирование JSON тела запроса
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := context.Background()
		lessonCollection := client.Database("INAI").Collection("lessons")

		// Определение диапазона дней недели в зависимости от номера недели
		var dayRange bson.M
		if requestBody.Week%2 == 0 {
			dayRange = bson.M{"$gte": 1, "$lte": 7}
		} else {
			dayRange = bson.M{"$gte": 8, "$lte": 14}
		}
		// Создание фильтра для запроса
		filter := bson.M{
			"groups.name": requestBody.Group,
			"day_of_week": dayRange,
		}

		// Поиск уроков в базе данных с фильтрацией и сортировкой
		cursor, err := lessonCollection.Find(ctx, filter, options.Find().SetSort(bson.D{
			{"day_of_week", 1}, // Сортировка по дням недели
			{"startTime", 1},   // Сортировка по началу урока
		}))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cursor.Close(ctx)

		var lessons []Lesson
		if err = cursor.All(ctx, &lessons); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Отправка ответа с найденными уроками
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(lessons); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
*/
// Изменения урока
func updateLesson(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Println("Update lesson")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных урока из тела запроса
		var lesson Lesson
		if err := json.NewDecoder(r.Body).Decode(&lesson); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Получение ID урока из параметров URL
		lessonID, err := primitive.ObjectIDFromHex(ps.ByName("id"))
		if err != nil {
			http.Error(w, "Invalid lesson ID", http.StatusBadRequest)
			return
		}

		ctx := context.Background()

		// Проверка и получение ID для групп
		groupCollection := client.Database("INAI").Collection("groups")
		for i, group := range lesson.Groups {
			var dbGroup Group
			err := groupCollection.FindOne(ctx, bson.M{"name": group.Name}).Decode(&dbGroup)
			if err != nil {
				http.Error(w, "Group not found: "+group.Name, http.StatusBadRequest)
				return
			}
			lesson.Groups[i].ID = dbGroup.ID
		}

		// Проверка и получение ID для предмета
		subjectCollection := client.Database("INAI").Collection("subjects")
		var dbSubject Subject
		err = subjectCollection.FindOne(ctx, bson.M{"name": lesson.Subject.Name}).Decode(&dbSubject)
		if err != nil {
			http.Error(w, "Subject not found: "+lesson.Subject.Name, http.StatusBadRequest)
			return
		}
		lesson.Subject.ID = dbSubject.ID

		// Проверка и получение ID для комнаты
		roomCollection := client.Database("INAI").Collection("rooms")
		var dbRoom Room
		err = roomCollection.FindOne(ctx, bson.M{"name": lesson.Room.Name}).Decode(&dbRoom)
		if err != nil {
			http.Error(w, "Room not found: "+lesson.Room.Name, http.StatusBadRequest)
			return
		}
		lesson.Room.ID = dbRoom.ID

		// Проверка и получение ID для учителя
		teacherCollection := client.Database("INAI").Collection("users")
		var dbTeacher User
		err = teacherCollection.FindOne(ctx, bson.M{"email": lesson.Teacher.Email}).Decode(&dbTeacher)
		if err != nil {
			http.Error(w, "Teacher not found: "+lesson.Teacher.Email, http.StatusBadRequest)
			return
		}
		lesson.Teacher.ID = dbTeacher.ID

		// Проверка занятости группы, учителя и комнаты
		lessonCollection := client.Database("INAI").Collection("lessons")

		// Создаем фильтр для поиска пересекающихся уроков, исключая текущий урок
		filter := bson.M{
			"_id":         bson.M{"$ne": lessonID},
			"day_of_week": lesson.DayOfWeek,
			"$or": []bson.M{
				{"groups._id": bson.M{"$in": getGroupIDs(lesson.Groups)}},
				{"teacher._id": lesson.Teacher.ID},
				{"room._id": lesson.Room.ID},
			},
			"startTime": lesson.StartTime,
		}

		// Проверяем наличие пересекающихся уроков
		var conflictingLesson Lesson
		err = lessonCollection.FindOne(ctx, filter).Decode(&conflictingLesson)
		if err == nil {
			http.Error(w, "Conflict: The group, teacher, or room is already booked at this time", http.StatusConflict)
			return
		} else if err != mongo.ErrNoDocuments {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Обновление урока в базе данных
		update := bson.M{
			"$set": lesson,
		}
		_, err = lessonCollection.UpdateOne(ctx, bson.M{"_id": lessonID}, update)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Отправка успешного ответа
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Lesson updated successfully"))
	}
}

// Функция для получения ID групп
func getGroupIDs(groups []Group) []primitive.ObjectID {
	var ids []primitive.ObjectID
	for _, group := range groups {
		ids = append(ids, group.ID)
	}
	return ids
}

// Удаление урока
func deleteLesson(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fmt.Println("Delete Lesson")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Получение ID урока из параметров URL
		lessonID, err := primitive.ObjectIDFromHex(ps.ByName("id"))
		if err != nil {
			http.Error(w, "Invalid lesson ID", http.StatusBadRequest)
			return
		}

		ctx := context.Background()

		// Удаление урока из базы данных
		lessonCollection := client.Database("INAI").Collection("lessons")
		_, err = lessonCollection.DeleteOne(ctx, bson.M{"_id": lessonID})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Отправка успешного ответа
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Lesson deleted successfully"))
	}
}

// Получение всех преподавателей
func getAllTeachers(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get All Teachers")
		// Получение коллекции "Teacher" из базы данных
		usersCollection := client.Database("INAI").Collection("users")

		// Поиск всех документов в коллекции
		cursor, err := usersCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		var users []User

		// Создание списка для хранения основных данных учителей
		var teacherBasics []struct {
			ID      primitive.ObjectID `json:"_id"`
			Name    string             `json:"name"`
			Surname string             `json:"surname"`
		}

		for cursor.Next(context.Background()) {
			var user User
			err := cursor.Decode(&user)
			if err != nil {
				http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
				log.Println("Failed to get subjects:", err)
				return
			}
			if user.Role == "teacher" {

				teacherBasics = append(teacherBasics, struct {
					ID      primitive.ObjectID `json:"_id"`
					Name    string             `json:"name"`
					Surname string             `json:"surname"`
				}{
					ID:      user.ID,
					Name:    user.Name,
					Surname: user.Surname,
				})
			}

		}
		fmt.Println(users)

		// Сериализация списка предметов в JSON
		usersJSON, err := json.Marshal(teacherBasics)
		if err != nil {
			http.Error(w, "Failed to serialize rooms", http.StatusInternalServerError)
			log.Println("Failed to serialize rooms:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(usersJSON)
	}
}

// Получение всех комнат
func getAllRooms(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get All Rooms")
		// Получение коллекции "subjects" из базы данных
		roomsCollection := client.Database("INAI").Collection("rooms")

		// Поиск всех документов в коллекции
		cursor, err := roomsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список предметов для сохранения результатов
		var rooms []Room

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var room Room
			if err := cursor.Decode(&room); err != nil {
				http.Error(w, "Failed to decode room", http.StatusInternalServerError)
				log.Println("Failed to decode room:", err)
				return
			}
			rooms = append(rooms, room)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over subjects", http.StatusInternalServerError)
			log.Println("Failed to iterate over subjects:", err)
			return
		}

		// Сериализация списка предметов в JSON
		subjectsJSON, err := json.Marshal(rooms)
		if err != nil {
			http.Error(w, "Failed to serialize rooms", http.StatusInternalServerError)
			log.Println("Failed to serialize rooms:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(subjectsJSON)
	}
}

// Получение всех комнат
func getAllLessons(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get All Lessons")
		// Получение коллекции "subjects" из базы данных
		roomsCollection := client.Database("INAI").Collection("lessons")

		// Поиск всех документов в коллекции
		cursor, err := roomsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список предметов для сохранения результатов
		var lessons []Lesson

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var lesson Lesson
			if err := cursor.Decode(&lesson); err != nil {
				http.Error(w, "Failed to decode room", http.StatusInternalServerError)
				log.Println("Failed to decode room:", err)
				return
			}
			lessons = append(lessons, lesson)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over subjects", http.StatusInternalServerError)
			log.Println("Failed to iterate over subjects:", err)
			return
		}

		// Сериализация списка предметов в JSON
		subjectsJSON, err := json.Marshal(lessons)
		if err != nil {
			http.Error(w, "Failed to serialize rooms", http.StatusInternalServerError)
			log.Println("Failed to serialize rooms:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(subjectsJSON)
	}
}

// Получение всех предметов
func getAllSubjects(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Get All Subjects")
		// Получение коллекции "subjects" из базы данных
		subjectsCollection := client.Database("INAI").Collection("subjects")

		// Поиск всех документов в коллекции
		cursor, err := subjectsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get subjects", http.StatusInternalServerError)
			log.Println("Failed to get subjects:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список предметов для сохранения результатов
		var subjects []Subject

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var subject Subject
			if err := cursor.Decode(&subject); err != nil {
				http.Error(w, "Failed to decode subject", http.StatusInternalServerError)
				log.Println("Failed to decode subject:", err)
				return
			}
			subjects = append(subjects, subject)
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over subjects", http.StatusInternalServerError)
			log.Println("Failed to iterate over subjects:", err)
			return
		}

		// Сериализация списка предметов в JSON
		subjectsJSON, err := json.Marshal(subjects)
		if err != nil {
			http.Error(w, "Failed to serialize subjects", http.StatusInternalServerError)
			log.Println("Failed to serialize subjects:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(subjectsJSON)
	}
}

// Получение Первого курса
func getFirstGroups(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "groups" из базы данных
		fmt.Println("Get 1 groups")
		groupsCollection := client.Database("INAI").Collection("groups")

		// Поиск всех документов в коллекции
		cursor, err := groupsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get groups", http.StatusInternalServerError)
			log.Println("Failed to get groups:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список групп для сохранения результатов
		var groups []Group

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var group Group
			if err := cursor.Decode(&group); err != nil {
				http.Error(w, "Failed to decode group", http.StatusInternalServerError)
				log.Println("Failed to decode group:", err)
				return
			}
			if group.Course == 1 {
				groups = append(groups, group)
			}
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over groups", http.StatusInternalServerError)
			log.Println("Failed to iterate over groups:", err)
			return
		}

		// Сериализация списка групп в JSON
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			http.Error(w, "Failed to serialize groups", http.StatusInternalServerError)
			log.Println("Failed to serialize groups:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(groupsJSON)
	}
}

// Получение второго курса
func getSecondGroups(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "groups" из базы данных
		fmt.Println("Get 2 groups")
		groupsCollection := client.Database("INAI").Collection("groups")

		// Поиск всех документов в коллекции
		cursor, err := groupsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get groups", http.StatusInternalServerError)
			log.Println("Failed to get groups:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список групп для сохранения результатов
		var groups []Group

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var group Group
			if err := cursor.Decode(&group); err != nil {
				http.Error(w, "Failed to decode group", http.StatusInternalServerError)
				log.Println("Failed to decode group:", err)
				return
			}
			if group.Course == 2 {
				groups = append(groups, group)
			}
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over groups", http.StatusInternalServerError)
			log.Println("Failed to iterate over groups:", err)
			return
		}

		// Сериализация списка групп в JSON
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			http.Error(w, "Failed to serialize groups", http.StatusInternalServerError)
			log.Println("Failed to serialize groups:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(groupsJSON)
	}
}

// Получение третьего курса
func getThirdGroups(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "groups" из базы данных
		fmt.Println("Get 3 groups")
		groupsCollection := client.Database("INAI").Collection("groups")

		// Поиск всех документов в коллекции
		cursor, err := groupsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get groups", http.StatusInternalServerError)
			log.Println("Failed to get groups:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список групп для сохранения результатов
		var groups []Group

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var group Group
			if err := cursor.Decode(&group); err != nil {
				http.Error(w, "Failed to decode group", http.StatusInternalServerError)
				log.Println("Failed to decode group:", err)
				return
			}
			if group.Course == 3 {
				groups = append(groups, group)
			}
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over groups", http.StatusInternalServerError)
			log.Println("Failed to iterate over groups:", err)
			return
		}

		// Сериализация списка групп в JSON
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			http.Error(w, "Failed to serialize groups", http.StatusInternalServerError)
			log.Println("Failed to serialize groups:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(groupsJSON)
	}
}

// Получение Четвертого курса
func getFourthGroups(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Получение коллекции "groups" из базы данных
		fmt.Println("Get 4 groups")
		groupsCollection := client.Database("INAI").Collection("groups")

		// Поиск всех документов в коллекции
		cursor, err := groupsCollection.Find(context.Background(), bson.M{})
		if err != nil {
			http.Error(w, "Failed to get groups", http.StatusInternalServerError)
			log.Println("Failed to get groups:", err)
			return
		}
		defer cursor.Close(context.Background())

		// Список групп для сохранения результатов
		var groups []Group

		// Итерация по результатам запроса
		for cursor.Next(context.Background()) {
			var group Group
			if err := cursor.Decode(&group); err != nil {
				http.Error(w, "Failed to decode group", http.StatusInternalServerError)
				log.Println("Failed to decode group:", err)
				return
			}
			if group.Course == 4 {
				groups = append(groups, group)
			}
		}
		if err := cursor.Err(); err != nil {
			http.Error(w, "Failed to iterate over groups", http.StatusInternalServerError)
			log.Println("Failed to iterate over groups:", err)
			return
		}

		// Сериализация списка групп в JSON
		groupsJSON, err := json.Marshal(groups)
		if err != nil {
			http.Error(w, "Failed to serialize groups", http.StatusInternalServerError)
			log.Println("Failed to serialize groups:", err)
			return
		}

		// Установка заголовка Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправка JSON в качестве ответа
		w.Write(groupsJSON)
	}
}

// Добавить урок
func addLesson(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Add Lesson")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var lesson Lesson
		if err := json.NewDecoder(r.Body).Decode(&lesson); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		ctx := context.Background()

		// Проверка и получение ID для групп
		groupCollection := client.Database("INAI").Collection("groups")
		for i, group := range lesson.Groups {
			var dbGroup Group
			err := groupCollection.FindOne(ctx, bson.M{"name": group.Name}).Decode(&dbGroup)
			if err != nil {
				http.Error(w, "Group not found: "+group.Name, http.StatusBadRequest)
				return
			}
			lesson.Groups[i].ID = dbGroup.ID
		}

		// Проверка и получение ID для предмета
		subjectCollection := client.Database("INAI").Collection("subjects")
		var dbSubject Subject
		err = subjectCollection.FindOne(ctx, bson.M{"name": lesson.Subject.Name}).Decode(&dbSubject)
		if err != nil {
			http.Error(w, "Subject not found: "+lesson.Subject.Name, http.StatusBadRequest)
			return
		}
		lesson.Subject.ID = dbSubject.ID

		// Проверка и получение ID для комнаты
		roomCollection := client.Database("INAI").Collection("rooms")
		var dbRoom Room
		err = roomCollection.FindOne(ctx, bson.M{"name": lesson.Room.Name}).Decode(&dbRoom)
		if err != nil {
			http.Error(w, "Room not found: "+lesson.Room.Name, http.StatusBadRequest)
			return
		}
		lesson.Room.ID = dbRoom.ID

		// Проверка и получение ID для учителя
		teacherCollection := client.Database("INAI").Collection("users")
		var dbTeacher User
		err = teacherCollection.FindOne(ctx, bson.M{"email": lesson.Teacher.Email}).Decode(&dbTeacher)
		if err != nil {
			http.Error(w, "Teacher not found: "+lesson.Teacher.Email, http.StatusBadRequest)
			return
		}
		lesson.Teacher.ID = dbTeacher.ID

		// Проверка занятости группы, учителя и комнаты
		lessonCollection := client.Database("INAI").Collection("lessons")

		// Создаем фильтр для поиска пересекающихся уроков
		filter := bson.M{
			"day_of_week": lesson.DayOfWeek,
			"$or": []bson.M{
				{"groups._id": bson.M{"$in": getGroupIDs(lesson.Groups)}},
				{"teacher._id": lesson.Teacher.ID},
				{"room._id": lesson.Room.ID},
			},
			"startTime": lesson.StartTime,
		}

		// Проверяем наличие пересекающихся уроков
		var conflictingLesson Lesson
		err = lessonCollection.FindOne(ctx, filter).Decode(&conflictingLesson)
		if err == nil {
			http.Error(w, "Conflict: The group, teacher, or room is already booked at this time", http.StatusConflict)
			return
		} else if err != mongo.ErrNoDocuments {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Сохранение урока в базу данных
		_, err = lessonCollection.InsertOne(ctx, lesson)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Отправка успешного ответа
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Lesson added successfully"))

	}
}

// Добавить комната
func addRoom(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Add Room")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var room Room
		if err := json.NewDecoder(r.Body).Decode(&room); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже предмет
		collection := client.Database("INAI").Collection("rooms")
		filter := bson.M{"name": room.Name}
		var existingRoom Room
		err = collection.FindOne(context.Background(), filter).Decode(&existingRoom)
		if err == nil {
			http.Error(w, "Room with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление группы в базу данных
		_, err = collection.InsertOne(context.Background(), room)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Subjects added successfully"))
	}
}

// Добавить Предмет
func addSubject(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Add Subject")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var subject Subject
		if err := json.NewDecoder(r.Body).Decode(&subject); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже предмет
		collection := client.Database("INAI").Collection("subjects")
		filter := bson.M{"name": subject.Name}
		var existingSubject Subject
		err = collection.FindOne(context.Background(), filter).Decode(&existingSubject)
		if err == nil {
			http.Error(w, "Subject with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление группы в базу данных
		_, err = collection.InsertOne(context.Background(), subject)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Subjects added successfully"))
	}
}

// Добавить Группу
func addGroup(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Println("Add Group")
		// Проверка авторизации и роли
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка роли
		claims, ok := token.Claims.(*Claims)
		if !ok || claims.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Декодирование данных о группе из тела запроса
		var group Group
		if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Проверка, существует ли уже группа
		collection := client.Database("INAI").Collection("groups")
		filter := bson.M{"name": group.Name}
		var existingGroup Group
		err = collection.FindOne(context.Background(), filter).Decode(&existingGroup)
		if err == nil {
			http.Error(w, "Group with the same name already exists", http.StatusBadRequest)
			return
		}

		// Добавление группы в базу данных
		_, err = collection.InsertOne(context.Background(), group)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Ответ об успешном добавлении группы
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Group added successfully"))
	}
}

// Middleware для проверки токена
func isAuthorized(next httprouter.Handle) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		// Проверка наличия токена в заголовке авторизации
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка токена
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Проверка срока действия токена
		if !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Продолжение выполнения запроса
		next(w, r, ps)
	}
}

// Логин
func handleLogin(client *mongo.Client) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		// Декодирование JSON данных из тела запроса

		fmt.Println("login get")
		var loginInfo struct {
			Email  string `json:"email"`
			Passwd string `json:"pass"`
		}
		fmt.Println(r.Body)
		err := json.NewDecoder(r.Body).Decode(&loginInfo)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Println(loginInfo)

		// Поиск в коллекции людей
		peopleCollection := client.Database("INAI").Collection("users")
		var person User
		err = peopleCollection.FindOne(context.Background(), bson.M{"email": loginInfo.Email}).Decode(&person)
		if err != nil {
			http.Error(w, "User not found1", http.StatusUnauthorized)
			return
		}

		// Проверка пароля
		err = bcrypt.CompareHashAndPassword([]byte(person.Pass), []byte(loginInfo.Passwd))
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Генерация JWT токена
		expirationTime := time.Now().Add(15 * time.Minute) // Время жизни токена
		claims := &Claims{
			Role:  person.Role,
			Email: person.Email,
			Group: person.Group,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: expirationTime.Unix(),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Создаем экземпляр структуры Response
		response := Response{
			Token: tokenString,
		}
		// Сериализуем структуру в JSON
		responseJSON, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "Failed to serialize response", http.StatusInternalServerError)
			return
		}

		// Устанавливаем заголовок Content-Type на application/json
		w.Header().Set("Content-Type", "application/json")

		// Отправляем JSON в качестве ответа
		w.Write(responseJSON)
	}
}

// Регистрация пользователя
func registerUser(w http.ResponseWriter, r *http.Request, client *mongo.Client) {
	fmt.Println("Register User")
	var user User
	user.ID = primitive.NewObjectID()
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	collection := client.Database("INAI").Collection("users")

	// Проверка, существует ли уже человек с таким email
	filter := bson.M{"email": user.Email}
	var existingUser User
	err = collection.FindOne(context.Background(), filter).Decode(&existingUser)
	if err == nil {
		http.Error(w, "Person with the same email already exists", http.StatusBadRequest)
		return
	}

	// Хеширование пароля
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Pass), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	user.Pass = string(hashedPassword)

	// Сохранение данных в базе данных
	_, err = collection.InsertOne(context.Background(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Отправка успешного ответа
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("User registered successfully"))
}
